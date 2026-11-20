/**
 * SafeKey Argon2 Worker
 * Runs Argon2id off the UI thread so the app stays responsive while a key is derived.
 */

importScripts('../vendor/argon2-bundled.min.js');

self.onmessage = async (event) => {
    const { id, pass, salt, mem, time, parallelism, hashLen } = event.data;
    try {
        const result = await self.argon2.hash({
            pass, salt, mem, time, parallelism, hashLen,
            type: self.argon2.ArgonType.Argon2id,
            distrib: false
        });
        self.postMessage({ id, hash: result.hash });
    } catch (error) {
        self.postMessage({ id, error: String((error && error.message) || error) });
    }
};
