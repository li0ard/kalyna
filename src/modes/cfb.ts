import type { KalynaBase } from "../core.js";

/**
 * Encrypts data using Cipher Feedback (CFB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 * @param iv Initialization vector
 * @param q Param `q`
 */
export const encryptCFB = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array, q: number = cipherClass.blockSize): Uint8Array => {
    const blockSize = cipherClass.blockSize;
    if (q !== 1 && q !== 8 && q !== 16 && q !== 32 && q !== 64) throw new Error('q must be 1, 8, 16, 32, or 64');
    if (q > blockSize) throw new Error('q cannot exceed block size');

    let gamma = cipherClass.encrypt(iv);
    const feed = new Uint8Array(iv);
    let offset = 0;
    const result = new Uint8Array(data.length);
    let dataOff = 0;

    while (offset > 0 && dataOff < data.length) {
        result[dataOff] = data[dataOff] ^ gamma[offset];
        feed[offset++] = result[dataOff++];
        
        if (offset >= blockSize) {
            gamma = cipherClass.encrypt(feed);
            offset = blockSize - q;
        }
    }

    while (dataOff + q <= data.length) {
        for (let i = 0; i < q; i++) result[dataOff + i] = data[dataOff + i] ^ gamma[blockSize - q + i];
        feed.set(gamma.slice(0, blockSize - q));
        feed.set(result.slice(dataOff, dataOff + q), blockSize - q);
        
        gamma = cipherClass.encrypt(feed);
        dataOff += q;
    }

    while (dataOff < data.length) {
        result[dataOff] = data[dataOff] ^ gamma[blockSize - (data.length - dataOff)];
        dataOff++;
    }

    return result;
}

/**
 * Decrypts data using Cipher Feedback (CFB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be decrypt
 * @param iv Initialization vector
 * @param q Param `q`
 */
export const decryptCFB = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array, q: number = cipherClass.blockSize): Uint8Array => {
    const blockSize = cipherClass.blockSize;
    if (q !== 1 && q !== 8 && q !== 16 && q !== 32 && q !== 64) throw new Error('q must be 1, 8, 16, 32, or 64');
    if (q > blockSize) throw new Error('q cannot exceed block size');

    let gamma = cipherClass.encrypt(iv);
    const feed = new Uint8Array(iv);
    let offset = 0;
    const result = new Uint8Array(data.length);
    let dataOff = 0;

    while (offset > 0 && dataOff < data.length) {
        result[dataOff] = data[dataOff] ^ gamma[offset];
        feed[offset++] = data[dataOff++];
        
        if (offset >= blockSize) {
            gamma = cipherClass.encrypt(feed);
            offset = blockSize - q;
        }
    }

    while (dataOff + q <= data.length) {
        for (let i = 0; i < q; i++) result[dataOff + i] = data[dataOff + i] ^ gamma[blockSize - q + i];
        feed.set(gamma.slice(0, blockSize - q));
        feed.set(data.subarray(dataOff, dataOff + q), blockSize - q);
        
        gamma = cipherClass.encrypt(feed);
        dataOff += q;
    }

    while (dataOff < data.length) {
        result[dataOff] = data[dataOff] ^ gamma[blockSize - (data.length - dataOff)];
        dataOff++;
    }

    return result;
}