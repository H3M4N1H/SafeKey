/**
 * SafeKey Cryptographic Utilities
 *
 * Implements secure cryptographic operations using Web Crypto API:
 * - Argon2id key derivation (memory-hard, modern default)
 * - PBKDF2 key derivation (legacy, for existing vaults)
 * - AES-256-GCM authenticated encryption
 * - Cryptographically secure random generation
 *
 * KDF selection:
 *   The master key derives a key-encryption key with Argon2id
 *   (ARGON2_PARAMS, stored per vault so they can be raised later).
 *   Older vaults (Argon2id at LEGACY_ARGON2_PARAMS, or PBKDF2) are
 *   migrated automatically on their next unlock.
 */

const Crypto = (function() {
    'use strict';

    // Configuration
    const CONFIG = {
        ARGON2_HASH_LEN:   32,      // 256-bit output
        // Legacy PBKDF2
        PBKDF2_ITERATIONS: 600000,
        // Shared
        SALT_LENGTH: 32,            // 256-bit salt (used for both KDFs)
        IV_LENGTH:   12,
        KEY_LENGTH:  256,
        HASH_ALGORITHM: 'SHA-256'
    };

    // KDF type constants
    const KDF = {
        ARGON2ID: 'argon2id',
        PBKDF2:   'pbkdf2'
    };

    // Argon2id cost for master keys: 128 MiB, 4 passes (~2.7x the legacy cost)
    const ARGON2_PARAMS = Object.freeze({ mem: 131072, time: 4, parallelism: 1 });

    // Cost used by vaults created before ARGON2_PARAMS existed, and by recovery keys
    const LEGACY_ARGON2_PARAMS = Object.freeze({ mem: 65536, time: 3, parallelism: 1 });

    /**
     * Generates cryptographically secure random bytes
     * @param {number} length - Number of bytes to generate
     * @returns {Uint8Array} Random bytes
     */
    function generateRandomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    /**
     * Generates a new salt for key derivation
     * @returns {Uint8Array} 16-byte random salt
     */
    function generateSalt() {
        return generateRandomBytes(CONFIG.SALT_LENGTH);
    }

    /**
     * Generates a new IV for encryption
     * @returns {Uint8Array} 12-byte random IV
     */
    function generateIV() {
        return generateRandomBytes(CONFIG.IV_LENGTH);
    }

    /**
     * Converts ArrayBuffer to Base64 string
     * @param {ArrayBuffer|Uint8Array} buffer
     * @returns {string} Base64 encoded string
     */
    function arrayBufferToBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Converts Base64 string to Uint8Array
     * @param {string} base64
     * @returns {Uint8Array}
     */
    function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Converts string to Uint8Array using UTF-8 encoding
     * @param {string} str
     * @returns {Uint8Array}
     */
    function stringToBytes(str) {
        return new TextEncoder().encode(str);
    }

    /**
     * Converts Uint8Array to string using UTF-8 decoding
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    function bytesToString(bytes) {
        return new TextDecoder().decode(bytes);
    }

    let argon2Worker;
    let argon2RequestId = 0;
    const argon2Pending = new Map();

    /**
     * Lazily starts the Argon2 worker
     * @returns {Worker|null} null when workers are unavailable
     */
    function getArgon2Worker() {
        if (argon2Worker !== undefined) return argon2Worker;
        try {
            argon2Worker = new Worker('js/argon2-worker.js');
            argon2Worker.onmessage = (event) => {
                const request = argon2Pending.get(event.data.id);
                if (!request) return;
                argon2Pending.delete(event.data.id);
                if (event.data.error) request.reject(new Error(event.data.error));
                else request.resolve(event.data.hash);
            };
            argon2Worker.onerror = (event) => {
                argon2Pending.forEach(request => request.reject(new Error(event.message || 'Argon2 worker error')));
                argon2Pending.clear();
            };
        } catch {
            argon2Worker = null;
        }
        return argon2Worker;
    }

    function hashInWorker(worker, password, salt, params) {
        return new Promise((resolve, reject) => {
            const id = ++argon2RequestId;
            argon2Pending.set(id, { resolve, reject });
            worker.postMessage({
                id,
                pass: password,
                salt,
                mem: params.mem,
                time: params.time,
                parallelism: params.parallelism,
                hashLen: CONFIG.ARGON2_HASH_LEN
            });
        });
    }

    /**
     * Derives raw key bytes using Argon2id.
     * Requires the argon2-browser WASM library to be loaded.
     * @param {string} password
     * @param {Uint8Array} salt
     * @param {{mem: number, time: number, parallelism: number}} params
     * @returns {Promise<Uint8Array>} 32 raw key bytes
     */
    async function deriveBytesArgon2id(password, salt, params) {
        const worker = getArgon2Worker();
        if (worker) {
            try {
                return await hashInWorker(worker, password, salt, params);
            } catch (error) {
                // Wrong passwords never reach here; only a broken worker does, so fall back to the page
                console.error('[Crypto] Argon2 worker failed, hashing on the main thread:', error);
                argon2Worker = null;
            }
        }

        if (typeof window.argon2 === 'undefined') {
            throw new Error('Argon2 WASM library not loaded');
        }

        const result = await window.argon2.hash({
            pass:   password,
            salt:   salt,
            type:   window.argon2.ArgonType.Argon2id,
            mem:    params.mem,
            time:   params.time,
            parallelism: params.parallelism,
            hashLen: CONFIG.ARGON2_HASH_LEN,
            distrib: false  // Don't split into workers (keep deterministic)
        });
        return result.hash;
    }

    /**
     * Derives raw key bytes using legacy PBKDF2 (for migrating old vaults only).
     * Matches the key deriveKeyPBKDF2 produces for the same inputs.
     * @param {string} masterPassword
     * @param {Uint8Array} salt
     * @returns {Promise<Uint8Array>} 32 raw key bytes
     */
    async function deriveBytesPBKDF2(masterPassword, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw', stringToBytes(masterPassword), 'PBKDF2', false, ['deriveBits']
        );
        const bits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt, iterations: CONFIG.PBKDF2_ITERATIONS, hash: CONFIG.HASH_ALGORITHM },
            keyMaterial,
            CONFIG.KEY_LENGTH
        );
        return new Uint8Array(bits);
    }

    /**
     * Imports raw key bytes as a non-extractable AES-256-GCM key
     * @param {Uint8Array} bytes
     * @returns {Promise<CryptoKey>}
     */
    function importAesKey(bytes) {
        return crypto.subtle.importKey(
            'raw', bytes, { name: 'AES-GCM', length: CONFIG.KEY_LENGTH }, false, ['encrypt', 'decrypt']
        );
    }

    /**
     * Derives a key using Argon2id (memory-hard).
     * @param {string} masterPassword
     * @param {Uint8Array} salt
     * @param {{mem: number, time: number, parallelism: number}} [params=LEGACY_ARGON2_PARAMS]
     * @returns {Promise<CryptoKey>} AES-GCM key
     */
    async function deriveKeyArgon2id(masterPassword, salt, params = LEGACY_ARGON2_PARAMS) {
        return importAesKey(await deriveBytesArgon2id(masterPassword, salt, params));
    }

    /**
     * Derives a key using legacy PBKDF2 (for existing vaults only).
     * @param {string} masterPassword
     * @param {Uint8Array} salt
     * @returns {Promise<CryptoKey>} AES-GCM key
     */
    async function deriveKeyPBKDF2(masterPassword, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            stringToBytes(masterPassword),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            {
                name:       'PBKDF2',
                salt:       salt,
                iterations: CONFIG.PBKDF2_ITERATIONS,
                hash:       CONFIG.HASH_ALGORITHM
            },
            keyMaterial,
            { name: 'AES-GCM', length: CONFIG.KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Unified key derivation — dispatches to Argon2id or PBKDF2.
     * @param {string} masterPassword
     * @param {Uint8Array} salt
     * @param {string} [kdfType='argon2id'] - KDF.ARGON2ID or KDF.PBKDF2
     * @returns {Promise<CryptoKey>}
     */
    async function deriveKey(masterPassword, salt, kdfType = KDF.ARGON2ID) {
        if (kdfType === KDF.PBKDF2) {
            return deriveKeyPBKDF2(masterPassword, salt);
        }
        return deriveKeyArgon2id(masterPassword, salt);
    }

    /**
     * Encrypts data using AES-256-GCM
     * @param {string} plaintext - Data to encrypt
     * @param {CryptoKey} key - AES-GCM key
     * @returns {Promise<{ciphertext: string, iv: string}>} Encrypted data with IV
     */
    async function encrypt(plaintext, key) {
        const iv = generateIV();
        const plaintextBytes = stringToBytes(plaintext);

        const ciphertextBuffer = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            plaintextBytes
        );

        return {
            ciphertext: arrayBufferToBase64(ciphertextBuffer),
            iv: arrayBufferToBase64(iv)
        };
    }

    /**
     * Decrypts data using AES-256-GCM
     * @param {string} ciphertext - Base64 encoded ciphertext
     * @param {string} iv - Base64 encoded IV
     * @param {CryptoKey} key - AES-GCM key
     * @returns {Promise<string>} Decrypted plaintext
     */
    async function decrypt(ciphertext, iv, key) {
        const ciphertextBytes = base64ToArrayBuffer(ciphertext);
        const ivBytes = base64ToArrayBuffer(iv);

        const plaintextBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBytes
            },
            key,
            ciphertextBytes
        );

        return bytesToString(new Uint8Array(plaintextBuffer));
    }

    /**
     * Creates a hash of data for verification purposes
     * @param {string} data - Data to hash
     * @returns {Promise<string>} Base64 encoded hash
     */
    async function hash(data) {
        const dataBytes = stringToBytes(data);
        const hashBuffer = await crypto.subtle.digest(CONFIG.HASH_ALGORITHM, dataBytes);
        return arrayBufferToBase64(hashBuffer);
    }

    // Public API
    return {
        KDF,
        ARGON2_PARAMS,
        LEGACY_ARGON2_PARAMS,
        generateSalt,
        generateRandomBytes,
        deriveBytesArgon2id,
        deriveBytesPBKDF2,
        importAesKey,
        generateIV,
        deriveKey,
        deriveKeyArgon2id,
        deriveKeyPBKDF2,
        encrypt,
        decrypt,
        hash,
        arrayBufferToBase64,
        base64ToArrayBuffer
    };
})();

// Export for use in other modules
window.Crypto = Crypto;
