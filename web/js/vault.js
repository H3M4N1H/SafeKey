/**
 * SafeKey Vault Management
 *
 * Handles:
 * - Encrypted credential storage in localStorage
 * - CRUD operations for credentials with per-entry unique IVs
 * - Clipboard management with auto-clear
 * - KDF versioning: Argon2id (new) and PBKDF2 (legacy)
 *
 * Salt storage format (JSON):
 *   { salt: "<base64>", kdf: "argon2id" | "pbkdf2" }
 */

const Vault = (function () {
    'use strict';

    // Per-vault storage fields; each vault stores them as safekey_v_<vaultId>_<field>
    const VAULT_FIELDS = {
        VAULT_DATA: 'vault',
        VAULT_SALT: 'salt',
        VAULT_VERIFY: 'verify',
        VAULT_NOTES: 'notes',
        VAULT_RECOVERY: 'recovery',
        VAULT_ATTACHMENTS: 'attachments'
    };

    // Device-wide storage keys
    const VAULTS_KEY = 'safekey_vaults';          // [{id, name}]
    const LAST_VAULT_KEY = 'safekey_last_vault';
    const GEN_PRESETS_KEY = 'safekey_gen_presets';

    const MAX_VAULTS = 3;

    // Clipboard auto-clear timeout (30 seconds)
    const CLIPBOARD_TIMEOUT = 30000;
    let clipboardTimeoutId = null;

    let activeVaultId = null;

    /**
     * Storage key of a field in a vault
     * @param {string} field - a VAULT_FIELDS name
     * @param {string} [vaultId] - defaults to the selected vault
     * @returns {string}
     */
    function storageKey(field, vaultId = activeVaultId) {
        if (!vaultId) throw new Error('No vault selected');
        return `safekey_v_${vaultId}_${VAULT_FIELDS[field]}`;
    }

    /**
     * @returns {Array<{id: string, name: string}>} vaults on this device, oldest first
     */
    function listVaults() {
        try {
            const vaults = JSON.parse(localStorage.getItem(VAULTS_KEY) || '[]');
            return Array.isArray(vaults)
                ? vaults.filter(v => v && typeof v.id === 'string' && typeof v.name === 'string')
                : [];
        } catch {
            return [];
        }
    }

    function saveVaults(vaults) {
        localStorage.setItem(VAULTS_KEY, JSON.stringify(vaults));
    }

    function newVaultId() {
        return Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Moves a vault stored by older versions (unprefixed keys, single vault) into the vault list
     */
    function migrateSingleVault() {
        if (localStorage.getItem(VAULTS_KEY) !== null || localStorage.getItem('safekey_salt') === null) return;
        const id = newVaultId();
        Object.values(VAULT_FIELDS).forEach(field => {
            const value = localStorage.getItem(`safekey_${field}`);
            if (value !== null) localStorage.setItem(`safekey_v_${id}_${field}`, value);
        });
        saveVaults([{ id, name: localStorage.getItem('safekey_username') || 'My Vault' }]);
        localStorage.setItem(LAST_VAULT_KEY, id);
        Object.values(VAULT_FIELDS).forEach(field => localStorage.removeItem(`safekey_${field}`));
        localStorage.removeItem('safekey_username');
    }

    /**
     * Checks if any vault exists on this device (first run detection)
     * @returns {boolean}
     */
    function exists() {
        return listVaults().length > 0;
    }

    /**
     * @returns {boolean} true if another vault can be created on this device
     */
    function canCreateVault() {
        return listVaults().length < MAX_VAULTS;
    }

    /**
     * @param {string} name
     * @returns {boolean} true if a vault already uses this name (case-insensitive)
     */
    function isNameTaken(name) {
        const wanted = name.trim().toLowerCase();
        return listVaults().some(v => v.name.toLowerCase() === wanted);
    }

    /**
     * Selects the vault that unlock and all data operations apply to
     * @param {string} vaultId
     * @returns {boolean}
     */
    function selectVault(vaultId) {
        if (!listVaults().some(v => v.id === vaultId)) return false;
        activeVaultId = vaultId;
        localStorage.setItem(LAST_VAULT_KEY, vaultId);
        return true;
    }

    /**
     * @returns {string|null} id of the selected vault
     */
    function getActiveVaultId() {
        return activeVaultId;
    }

    /**
     * Gets the selected vault's name
     * @returns {string|null}
     */
    function getVaultName() {
        const vault = listVaults().find(v => v.id === activeVaultId);
        return vault ? vault.name : null;
    }

    /**
     * Removes every stored field of a vault
     * @param {string} vaultId
     */
    function removeVaultData(vaultId) {
        Object.keys(VAULT_FIELDS).forEach(field => localStorage.removeItem(storageKey(field, vaultId)));
    }

    /**
     * @returns {{kdf: string, params: Object|null}|null} KDF of the selected vault, for display
     */
    function getKdfInfo() {
        if (!activeVaultId) return null;
        const blob = readKeyBlob();
        return blob ? { kdf: blob.kdf, params: blob.params || null } : null;
    }

    /**
     * Reads the stored key blob. Current vaults store the Argon2id params and the
     * vault key wrapped by the master key; older vaults store only a salt (and KDF).
     * @returns {Object|null}
     */
    function readKeyBlob() {
        if (!activeVaultId) return null;
        const raw = localStorage.getItem(storageKey('VAULT_SALT'));
        if (raw === null) return null;
        try {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === 'object') {
                return { ...parsed, kdf: parsed.kdf || Crypto.KDF.PBKDF2 };
            }
        } catch {
            // Legacy vault: raw base64 salt (PBKDF2)
        }
        return { salt: raw, kdf: Crypto.KDF.PBKDF2 };
    }

    /**
     * Derives the raw vault key from the master password.
     * @param {string} masterPassword
     * @param {Object} blob - from readKeyBlob()
     * @returns {Promise<Uint8Array|null>} vault key bytes, or null if the password is wrong
     */
    async function openVaultKey(masterPassword, blob) {
        const salt = Crypto.base64ToArrayBuffer(blob.salt);
        if (blob.wrappedKey) {
            const kek = await Crypto.deriveKeyArgon2id(masterPassword, salt, blob.params);
            try {
                const keyBase64 = await Crypto.decrypt(blob.wrappedKey.ciphertext, blob.wrappedKey.iv, kek);
                return Crypto.base64ToArrayBuffer(keyBase64);
            } catch {
                return null;
            }
        }
        // Legacy vaults encrypted their data directly with the password-derived key
        if (blob.kdf === Crypto.KDF.PBKDF2) {
            return Crypto.deriveBytesPBKDF2(masterPassword, salt);
        }
        return Crypto.deriveBytesArgon2id(masterPassword, salt, Crypto.LEGACY_ARGON2_PARAMS);
    }

    /**
     * Checks raw vault key bytes against the stored verification token
     * @param {Uint8Array} keyBytes
     * @returns {Promise<CryptoKey|null>} the vault key, or null if it does not match
     */
    async function verifyVaultKey(keyBytes) {
        const key = await Crypto.importAesKey(keyBytes);
        try {
            const verifyData = JSON.parse(localStorage.getItem(storageKey('VAULT_VERIFY')));
            const verified = await Crypto.decrypt(verifyData.ciphertext, verifyData.iv, key);
            return verified === 'SAFEKEY_VERIFY_TOKEN' ? key : null;
        } catch {
            return null;
        }
    }

    /**
     * Wraps the vault key under a key derived from the master password at the current Argon2id cost
     * @param {Uint8Array} keyBytes
     * @param {string} masterPassword
     * @returns {Promise<string>} key blob to store under VAULT_SALT
     */
    async function buildKeyBlob(keyBytes, masterPassword) {
        const salt = Crypto.generateSalt();
        const params = { ...Crypto.ARGON2_PARAMS };
        const kek = await Crypto.deriveKeyArgon2id(masterPassword, salt, params);
        const wrappedKey = await Crypto.encrypt(Crypto.arrayBufferToBase64(keyBytes), kek);
        return JSON.stringify({
            v: 2,
            kdf: Crypto.KDF.ARGON2ID,
            salt: Crypto.arrayBufferToBase64(salt),
            params,
            wrappedKey
        });
    }

    /**
     * @param {Object} blob - from readKeyBlob()
     * @returns {boolean} true if the vault already uses a wrapped key at the current Argon2id cost
     */
    function usesCurrentKdf(blob) {
        const params = blob.params;
        const current = Crypto.ARGON2_PARAMS;
        return Boolean(blob.wrappedKey && params && params.mem >= current.mem && params.time >= current.time);
    }

    /**
     * Legacy recovery data wrapped the password-derived key, so it only still
     * matches the vault if the master key was never changed after it was made.
     * @param {Object} blob - from readKeyBlob()
     * @returns {boolean}
     */
    function legacyRecoveryMatches(blob) {
        try {
            const recovery = JSON.parse(localStorage.getItem(storageKey('VAULT_RECOVERY')));
            return Boolean(recovery) && blob.kdf === Crypto.KDF.ARGON2ID && recovery.vaultSalt === blob.salt;
        } catch {
            return false;
        }
    }

    /**
     * Creates and stores a new recovery key for the vault key
     * @param {Uint8Array} keyBytes
     * @returns {Promise<string>} the recovery key, to show the user once
     */
    async function createRecovery(keyBytes) {
        const recoveryKey = generateRecoveryKey();
        const recoverySalt = Crypto.generateSalt();
        const recoveryDerivedKey = await Crypto.deriveKey(recoveryKey, recoverySalt, Crypto.KDF.ARGON2ID);
        const encrypted = await Crypto.encrypt(Crypto.arrayBufferToBase64(keyBytes), recoveryDerivedKey);
        localStorage.setItem(storageKey('VAULT_RECOVERY'), JSON.stringify({
            salt: Crypto.arrayBufferToBase64(recoverySalt),
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv
        }));
        return recoveryKey;
    }

    /**
     * Creates a new vault and selects it. Never touches existing vaults.
     * @param {string} name - vault name shown in the vault picker
     * @param {string} masterPassword
     * @returns {Promise<{success: boolean, key?: CryptoKey, recoveryKey?: string, error?: string}>}
     */
    async function initialize(name, masterPassword) {
        name = name.trim();
        if (!canCreateVault()) {
            return { success: false, error: `This device already has ${MAX_VAULTS} vaults` };
        }
        if (isNameTaken(name)) {
            return { success: false, error: 'A vault with this name already exists' };
        }
        const previousVaultId = activeVaultId;
        const vaultId = newVaultId();
        activeVaultId = vaultId;
        try {
            // Random vault key; the master key and recovery key each wrap it
            const keyBytes = Crypto.generateRandomBytes(32);
            const key = await Crypto.importAesKey(keyBytes);
            const verifyData = await Crypto.encrypt('SAFEKEY_VERIFY_TOKEN', key);
            const keyBlob = await buildKeyBlob(keyBytes, masterPassword);

            localStorage.setItem(storageKey('VAULT_VERIFY'), JSON.stringify(verifyData));
            localStorage.setItem(storageKey('VAULT_DATA'), JSON.stringify([]));
            localStorage.setItem(storageKey('VAULT_NOTES'), JSON.stringify([]));
            localStorage.setItem(storageKey('VAULT_ATTACHMENTS'), JSON.stringify([]));
            const recoveryKey = await createRecovery(keyBytes);
            localStorage.setItem(storageKey('VAULT_SALT'), keyBlob);
            keyBytes.fill(0);

            // Listed last: the vault only appears once all its data is in place
            saveVaults([...listVaults(), { id: vaultId, name }]);
            selectVault(vaultId);

            return { success: true, key, kdf: Crypto.KDF.ARGON2ID, recoveryKey };
        } catch (error) {
            console.error('[Vault] Initialization failed:', error);
            removeVaultData(vaultId);
            activeVaultId = previousVaultId;
            return { success: false, error: 'Failed to create vault' };
        }
    }

    /**
     * Generates a human-readable recovery key
     * Format: 8 groups of 4 chars separated by dashes (e.g., ABCD-1234-EFGH-5678-IJKL-MNOP-QRST-UV23)
     * @returns {string}
     */
    function generateRecoveryKey() {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        let key = '';
        for (let i = 0; i < 32; i++) {
            if (i > 0 && i % 4 === 0) key += '-';
            key += alphabet[bytes[i] % alphabet.length];
        }
        return key;
    }

    /**
     * Recovers the vault using a recovery key, optionally setting a new master key
     * @param {string} recoveryKey
     * @param {string} [newMasterPassword]
     * @returns {Promise<{success: boolean, key?: CryptoKey, error?: string}>}
     */
    async function recoverWithKey(recoveryKey, newMasterPassword) {
        try {
            const recoveryDataStr = localStorage.getItem(storageKey('VAULT_RECOVERY'));
            if (!recoveryDataStr) {
                return { success: false, error: 'No recovery data found' };
            }

            const recoveryData = JSON.parse(recoveryDataStr);
            const recoverySalt = Crypto.base64ToArrayBuffer(recoveryData.salt);
            const recoveryDerivedKey = await Crypto.deriveKey(recoveryKey, recoverySalt, Crypto.KDF.ARGON2ID);

            let keyBytes;
            try {
                keyBytes = Crypto.base64ToArrayBuffer(
                    await Crypto.decrypt(recoveryData.ciphertext, recoveryData.iv, recoveryDerivedKey)
                );
            } catch (e) {
                return { success: false, error: 'Invalid recovery key' };
            }

            const key = await verifyVaultKey(keyBytes);
            if (!key) {
                return { success: false, error: 'Recovery key does not match this vault' };
            }

            if (newMasterPassword) {
                localStorage.setItem(storageKey('VAULT_SALT'), await buildKeyBlob(keyBytes, newMasterPassword));
            }
            keyBytes.fill(0);
            return { success: true, key };
        } catch (error) {
            console.error('[Vault] Recovery failed:', error);
            return { success: false, error: 'Recovery failed' };
        }
    }

    /**
     * Attempts to unlock the vault with master password. Vaults using an older
     * KDF are upgraded in place; if their recovery data no longer matched, a new
     * recovery key is created and returned so it can be shown to the user.
     * @param {string} masterPassword
     * @returns {Promise<{success: boolean, key?: CryptoKey, kdf?: string, upgraded?: boolean, recoveryKey?: string}>}
     */
    async function unlock(masterPassword) {
        try {
            const blob = readKeyBlob();
            if (!blob) return { success: false, error: 'No vault found' };

            const keyBytes = await openVaultKey(masterPassword, blob);
            const key = keyBytes && await verifyVaultKey(keyBytes);
            if (!key) return { success: false, error: 'Invalid master key' };

            let recoveryKey = null;
            const upgraded = !usesCurrentKdf(blob);
            if (upgraded) {
                if (!blob.wrappedKey && !legacyRecoveryMatches(blob)) {
                    recoveryKey = await createRecovery(keyBytes);
                }
                localStorage.setItem(storageKey('VAULT_SALT'), await buildKeyBlob(keyBytes, masterPassword));
            }
            keyBytes.fill(0);

            return { success: true, key, kdf: blob.kdf, upgraded, recoveryKey };
        } catch (error) {
            console.error('[Vault] Unlock failed:', error);
            return { success: false, error: 'Unlock failed' };
        }
    }

    /**
     * Gets all credentials (decrypted)
     * @returns {Promise<Array>}
     */
    async function getAll() {
        const key = Session.getKey();
        if (!key) {
            throw new Error('Vault is locked');
        }

        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_DATA')) || '[]');
        const decryptedCredentials = [];

        for (const entry of encryptedData) {
            try {
                const decrypted = await Crypto.decrypt(entry.data, entry.iv, key);
                decryptedCredentials.push({
                    id: entry.id,
                    ...JSON.parse(decrypted)
                });
            } catch (e) {
                console.error('[Vault] Failed to decrypt entry:', entry.id);
            }
        }

        return decryptedCredentials;
    }

    /**
     * Gets a single credential by ID
     * @param {string} id
     * @returns {Promise<Object|null>}
     */
    async function getById(id) {
        const all = await getAll();
        return all.find(c => c.id === id) || null;
    }

    /**
     * Adds a new credential
     * @param {Object} credential - {site, username, password, notes}
     * @returns {Promise<Object>} Created credential with ID
     */
    async function add(credential) {
        const key = Session.getKey();
        if (!key) {
            throw new Error('Vault is locked');
        }

        // Generate unique ID
        const id = generateId();

        // Prepare credential data
        const credentialData = {
            site: credential.site,
            url: credential.url || '',
            category: credential.category || '',
            tags: credential.tags || [],
            username: credential.username,
            password: credential.password,
            notes: credential.notes || '',
            totp: credential.totp || '',
            favorite: credential.favorite || false,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        // Encrypt with unique IV
        const encrypted = await Crypto.encrypt(JSON.stringify(credentialData), key);

        // Store encrypted entry
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_DATA')) || '[]');
        encryptedData.push({
            id,
            data: encrypted.ciphertext,
            iv: encrypted.iv
        });
        localStorage.setItem(storageKey('VAULT_DATA'), JSON.stringify(encryptedData));

        return { id, ...credentialData };
    }

    /**
     * Updates an existing credential
     * @param {string} id
     * @param {Object} updates
     * @returns {Promise<Object>} Updated credential
     */
    async function update(id, updates) {
        const key = Session.getKey();
        if (!key) {
            throw new Error('Vault is locked');
        }

        // Get current credential
        const current = await getById(id);
        if (!current) {
            throw new Error('Credential not found');
        }

        // Track password history if password changed
        if (updates.password && updates.password !== current.password) {
            const history = current.passwordHistory || [];
            history.push({
                password: current.password,
                changedAt: Date.now()
            });
            updates.passwordHistory = history;
        } else {
            // Preserve existing history
            updates.passwordHistory = current.passwordHistory || [];
        }

        // Merge updates
        const updatedCredential = {
            ...current,
            ...updates,
            updatedAt: Date.now()
        };
        delete updatedCredential.id; // Remove ID from data

        // Re-encrypt with new IV
        const encrypted = await Crypto.encrypt(JSON.stringify(updatedCredential), key);

        // Update storage
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_DATA')) || '[]');
        const index = encryptedData.findIndex(e => e.id === id);
        if (index !== -1) {
            encryptedData[index] = {
                id,
                data: encrypted.ciphertext,
                iv: encrypted.iv
            };
            localStorage.setItem(storageKey('VAULT_DATA'), JSON.stringify(encryptedData));
        }

        return { id, ...updatedCredential };
    }

    /**
     * Deletes a credential
     * @param {string} id
     * @returns {Promise<boolean>}
     */
    async function remove(id) {
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_DATA')) || '[]');
        const filtered = encryptedData.filter(e => e.id !== id);

        if (filtered.length !== encryptedData.length) {
            localStorage.setItem(storageKey('VAULT_DATA'), JSON.stringify(filtered));
            return true;
        }
        return false;
    }

    /**
     * Searches credentials by site or username
     * @param {string} query
     * @returns {Promise<Array>}
     */
    async function search(query) {
        const all = await getAll();
        const lowerQuery = query.toLowerCase();

        return all.filter(c =>
            c.site.toLowerCase().includes(lowerQuery) ||
            c.username.toLowerCase().includes(lowerQuery)
        );
    }

    /**
     * Copies password to clipboard with auto-clear
     * @param {string} text
     */
    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);

            // Clear any existing timeout
            if (clipboardTimeoutId) {
                clearTimeout(clipboardTimeoutId);
            }

            // Set up auto-clear
            clipboardTimeoutId = setTimeout(async () => {
                try {
                    await navigator.clipboard.writeText('');
                    console.log('[Vault] Clipboard cleared');
                } catch (e) {
                    // Ignore clipboard clear errors
                }
            }, CLIPBOARD_TIMEOUT);

            return true;
        } catch (error) {
            console.error('[Vault] Clipboard copy failed:', error);
            return false;
        }
    }

    /**
     * Generates a unique ID
     * @returns {string}
     */
    function generateId() {
        const randomBytes = new Uint8Array(9);
        crypto.getRandomValues(randomBytes);
        const randomPart = Array.from(randomBytes).map(b => b.toString(36)).join('');
        return 'cred_' + Date.now().toString(36) + '_' + randomPart;
    }

    /**
     * Exports vault data (encrypted blob)
     * @param {{includeAttachments?: boolean}} [options]
     * @returns {string} Encrypted vault data
     */
    function exportVault({ includeAttachments = true } = {}) {
        return JSON.stringify({
            format: 'safekey-vault',
            version: 2,
            name: getVaultName(),
            salt: localStorage.getItem(storageKey('VAULT_SALT')),
            verify: localStorage.getItem(storageKey('VAULT_VERIFY')),
            data: localStorage.getItem(storageKey('VAULT_DATA')),
            notes: localStorage.getItem(storageKey('VAULT_NOTES')) || '[]',
            attachments: includeAttachments ? (localStorage.getItem(storageKey('VAULT_ATTACHMENTS')) || '[]') : '[]',
            recovery: localStorage.getItem(storageKey('VAULT_RECOVERY'))
        });
    }

    /**
     * Parses a JSON array of encrypted entries and checks each entry's shape
     * @param {string} json
     * @returns {Array}
     */
    function parseEncryptedEntries(json) {
        const entries = JSON.parse(json);
        if (!Array.isArray(entries)) throw new Error('Invalid vault structure');
        for (const entry of entries) {
            if (!entry || typeof entry.id !== 'string' || !/^[A-Za-z0-9_-]+$/.test(entry.id) ||
                typeof entry.data !== 'string' || typeof entry.iv !== 'string') {
                throw new Error('Invalid vault entry');
            }
        }
        return entries;
    }

    /**
     * Imports vault data, replacing the selected vault
     * @param {string} exportedData
     * @returns {boolean}
     */
    function importVault(exportedData) {
        try {
            const data = JSON.parse(exportedData);
            if (typeof data.salt !== 'string' || typeof data.verify !== 'string' || typeof data.data !== 'string') {
                throw new Error('Invalid vault structure');
            }
            // Validate every field before touching storage
            const verify = JSON.parse(data.verify);
            if (!verify || typeof verify.ciphertext !== 'string' || typeof verify.iv !== 'string') {
                throw new Error('Invalid verification data');
            }
            parseEncryptedEntries(data.data);
            const notes = typeof data.notes === 'string' ? data.notes : '[]';
            parseEncryptedEntries(notes);
            // Attachments from other vaults could not be decrypted, so a backup without them clears them
            const attachments = typeof data.attachments === 'string' ? data.attachments : '[]';
            parseEncryptedEntries(attachments);
            const recovery = typeof data.recovery === 'string' ? data.recovery : null;
            if (recovery !== null && typeof JSON.parse(recovery) !== 'object') {
                throw new Error('Invalid recovery data');
            }

            localStorage.setItem(storageKey('VAULT_SALT'), data.salt);
            localStorage.setItem(storageKey('VAULT_VERIFY'), data.verify);
            localStorage.setItem(storageKey('VAULT_DATA'), data.data);
            localStorage.setItem(storageKey('VAULT_NOTES'), notes);
            localStorage.setItem(storageKey('VAULT_ATTACHMENTS'), attachments);
            if (recovery !== null) {
                localStorage.setItem(storageKey('VAULT_RECOVERY'), recovery);
            } else {
                localStorage.removeItem(storageKey('VAULT_RECOVERY'));
            }
            // Backups from older versions carry the name as username
            const importedName = typeof data.name === 'string' ? data.name : data.username;
            if (typeof importedName === 'string' && importedName.trim()) {
                const vaults = listVaults();
                const current = vaults.find(v => v.id === activeVaultId);
                const taken = vaults.some(v => v.id !== activeVaultId && v.name.toLowerCase() === importedName.trim().toLowerCase());
                if (current && !taken) {
                    current.name = importedName.trim();
                    saveVaults(vaults);
                }
            }
            return true;
        } catch (e) {
            console.error('[Vault] Import failed:', e);
            return false;
        }
    }

    /**
     * Changes the master key. Only the wrapped vault key changes, so stored
     * data and the recovery key stay valid.
     * @param {string} currentPassword
     * @param {string} newPassword
     * @returns {Promise<{success: boolean, key?: CryptoKey, recoveryKey?: string, error?: string}>}
     */
    async function changeMasterKey(currentPassword, newPassword) {
        try {
            const blob = readKeyBlob();
            if (!blob) return { success: false, error: 'No vault found' };

            const keyBytes = await openVaultKey(currentPassword, blob);
            const key = keyBytes && await verifyVaultKey(keyBytes);
            if (!key) return { success: false, error: 'Invalid current master key' };

            let recoveryKey = null;
            if (!blob.wrappedKey && !legacyRecoveryMatches(blob)) {
                recoveryKey = await createRecovery(keyBytes);
            }
            localStorage.setItem(storageKey('VAULT_SALT'), await buildKeyBlob(keyBytes, newPassword));
            keyBytes.fill(0);

            return { success: true, key, kdf: Crypto.KDF.ARGON2ID, recoveryKey };
        } catch (error) {
            console.error('[Vault] Change master key failed:', error);
            return { success: false, error: 'Failed to change master key' };
        }
    }

    // ─── Secure Notes ────────────────────────────────────────────────────────

    /**
     * Gets all notes (decrypted)
     * @returns {Promise<Array>}
     */
    async function getAllNotes() {
        const key = Session.getKey();
        if (!key) throw new Error('Vault is locked');

        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_NOTES')) || '[]');
        const decryptedNotes = [];

        for (const entry of encryptedData) {
            try {
                const decrypted = await Crypto.decrypt(entry.data, entry.iv, key);
                decryptedNotes.push({ id: entry.id, ...JSON.parse(decrypted) });
            } catch (e) {
                console.error('[Vault] Failed to decrypt note:', entry.id);
            }
        }

        return decryptedNotes;
    }

    /**
     * Gets a single note by ID
     * @param {string} id
     * @returns {Promise<Object|null>}
     */
    async function getNoteById(id) {
        const all = await getAllNotes();
        return all.find(n => n.id === id) || null;
    }

    /**
     * Adds a new note
     * @param {Object} note - {title, content}
     * @returns {Promise<Object>}
     */
    async function addNote(note) {
        const key = Session.getKey();
        if (!key) throw new Error('Vault is locked');

        const id = generateId().replace('cred_', 'note_');
        const noteData = {
            title: note.title,
            content: note.content,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        const encrypted = await Crypto.encrypt(JSON.stringify(noteData), key);
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_NOTES')) || '[]');
        encryptedData.push({ id, data: encrypted.ciphertext, iv: encrypted.iv });
        localStorage.setItem(storageKey('VAULT_NOTES'), JSON.stringify(encryptedData));

        return { id, ...noteData };
    }

    /**
     * Updates an existing note
     * @param {string} id
     * @param {Object} updates
     * @returns {Promise<Object>}
     */
    async function updateNote(id, updates) {
        const key = Session.getKey();
        if (!key) throw new Error('Vault is locked');

        const current = await getNoteById(id);
        if (!current) throw new Error('Note not found');

        const updatedNote = { ...current, ...updates, updatedAt: Date.now() };
        delete updatedNote.id;

        const encrypted = await Crypto.encrypt(JSON.stringify(updatedNote), key);
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_NOTES')) || '[]');
        const index = encryptedData.findIndex(e => e.id === id);
        if (index !== -1) {
            encryptedData[index] = { id, data: encrypted.ciphertext, iv: encrypted.iv };
            localStorage.setItem(storageKey('VAULT_NOTES'), JSON.stringify(encryptedData));
        }

        return { id, ...updatedNote };
    }

    /**
     * Deletes a note
     * @param {string} id
     * @returns {Promise<boolean>}
     */
    async function removeNote(id) {
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_NOTES')) || '[]');
        const filtered = encryptedData.filter(e => e.id !== id);
        if (filtered.length !== encryptedData.length) {
            localStorage.setItem(storageKey('VAULT_NOTES'), JSON.stringify(filtered));
            return true;
        }
        return false;
    }

    // ─── File Attachments ─────────────────────────────────────────────────────

    async function getAllAttachments() {
        const key = Session.getKey();
        if (!key) throw new Error('Vault is locked');
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_ATTACHMENTS')) || '[]');
        const decrypted = [];
        for (const entry of encryptedData) {
            try {
                const d = await Crypto.decrypt(entry.data, entry.iv, key);
                decrypted.push({ id: entry.id, ...JSON.parse(d) });
            } catch (e) {
                console.error('[Vault] Failed to decrypt attachment:', entry.id);
            }
        }
        return decrypted;
    }

    async function getAttachmentsByCredId(credId) {
        const all = await getAllAttachments();
        return all.filter(a => a.credentialId === credId);
    }

    async function addAttachment(credentialId, fileName, fileType, dataBase64) {
        const key = Session.getKey();
        if (!key) throw new Error('Vault is locked');
        const id = generateId().replace('cred_', 'att_');
        const attData = {
            credentialId,
            fileName,
            fileType,
            data: dataBase64,
            createdAt: Date.now()
        };
        const encrypted = await Crypto.encrypt(JSON.stringify(attData), key);
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_ATTACHMENTS')) || '[]');
        encryptedData.push({ id, data: encrypted.ciphertext, iv: encrypted.iv });
        localStorage.setItem(storageKey('VAULT_ATTACHMENTS'), JSON.stringify(encryptedData));
        return { id, ...attData };
    }

    async function removeAttachment(id) {
        const encryptedData = JSON.parse(localStorage.getItem(storageKey('VAULT_ATTACHMENTS')) || '[]');
        const filtered = encryptedData.filter(e => e.id !== id);
        if (filtered.length !== encryptedData.length) {
            localStorage.setItem(storageKey('VAULT_ATTACHMENTS'), JSON.stringify(filtered));
            return true;
        }
        return false;
    }

    // ─── Vault Wipe ──────────────────────────────────────────────────────────

    /**
     * Permanently deletes the selected vault; other vaults on the device are untouched
     */
    function wipeVault() {
        if (!activeVaultId) return;
        const vaultId = activeVaultId;
        saveVaults(listVaults().filter(v => v.id !== vaultId));
        removeVaultData(vaultId);
        const remaining = listVaults();
        activeVaultId = null;
        if (remaining.length) selectVault(remaining[0].id);
        else localStorage.removeItem(LAST_VAULT_KEY);
        console.log('[Vault] Vault wiped');
    }

    // ─── Generator Presets ───────────────────────────────────────────────────

    function getGenPresets() {
        try { return JSON.parse(localStorage.getItem(GEN_PRESETS_KEY) || '[]'); }
        catch { return []; }
    }

    function saveGenPreset(preset) {
        const presets = getGenPresets();
        preset.id = Date.now().toString(36);
        presets.push(preset);
        localStorage.setItem(GEN_PRESETS_KEY, JSON.stringify(presets));
        return preset;
    }

    function deleteGenPreset(id) {
        const presets = getGenPresets().filter(p => p.id !== id);
        localStorage.setItem(GEN_PRESETS_KEY, JSON.stringify(presets));
    }

    // Start with the most recently used vault selected
    migrateSingleVault();
    {
        const vaults = listVaults();
        const last = localStorage.getItem(LAST_VAULT_KEY);
        if (vaults.length) selectVault(vaults.some(v => v.id === last) ? last : vaults[0].id);
    }

    // Public API
    return {
        MAX_VAULTS,
        exists,
        canCreateVault,
        isNameTaken,
        listVaults,
        selectVault,
        getActiveVaultId,
        getVaultName,
        getKdfInfo,
        initialize,
        unlock,
        recoverWithKey,
        getAll,
        getById,
        add,
        update,
        remove,
        search,
        copyToClipboard,
        exportVault,
        importVault,
        changeMasterKey,
        getAllNotes,
        getNoteById,
        addNote,
        updateNote,
        removeNote,
        getAllAttachments,
        getAttachmentsByCredId,
        addAttachment,
        removeAttachment,
        wipeVault,
        getGenPresets,
        saveGenPreset,
        deleteGenPreset
    };
})();

// Export for use in other modules
window.Vault = Vault;
