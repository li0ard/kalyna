import { concatBytes, xor } from "@li0ard/gost3413/dist/utils.js";
import type { KalynaBase } from "../core.js";
import { ctr } from "../index.js";
import { equalBytes, gf2mMul, numberToBytesLE } from "../utils.js";

/**
 * Compute GMAC
 * @param cipherClass Initialized cipher class
 * @param authData Data to be authenticated
 * @param cipherData Ciphertext to be authenticated (Only for GMAC)
 * @param q MAC size
 */
export const gmac = (cipherClass: KalynaBase, authData: Uint8Array, cipherData: Uint8Array = new Uint8Array(), q: number = 16): Uint8Array => {
    const blockSize = cipherClass.blockSize;
    const H = cipherClass.encrypt(new Uint8Array(blockSize));

    let B: Uint8Array = new Uint8Array(blockSize);
    let i = 0;
    while (i < authData.length) {
        const blockSizeToProcess = Math.min(blockSize, authData.length - i);
        const block = new Uint8Array(blockSize);
        
        for (let j = 0; j < blockSizeToProcess; j++) block[j] = authData[i + j];
        if (blockSizeToProcess < blockSize) block[blockSizeToProcess] = 0x80; 
        for (let j = 0; j < blockSize; j++) B[j] ^= block[j];
        B = gf2mMul(blockSize, B, H);
        
        i += blockSize;
    }

    i = 0;
    while (i < cipherData.length) {
        const blockSizeToProcess = Math.min(blockSize, cipherData.length - i);
        const block = new Uint8Array(blockSize);
        
        for (let j = 0; j < blockSizeToProcess; j++) block[j] = cipherData[i + j];
        if (blockSizeToProcess < blockSize) block[blockSizeToProcess] = 0x80; 
        for (let j = 0; j < blockSize; j++) B[j] ^= block[j];
        B = gf2mMul(blockSize, B, H);
        
        i += blockSize;
    }

    B = xor(B, concatBytes(numberToBytesLE(authData.length * 8, blockSize / 2), numberToBytesLE(cipherData.length * 8, blockSize / 2)));
    // B = gf2mMul(blockSize, B, H);

    return cipherClass.encrypt(B).slice(0, q);
}

/**
 * Encrypts data using Galois/Counter Mode (GCM) mode
 * @param cipherClass Initialized cipher class
 * @param plainData Data to be encrypted and authenticated
 * @param iv Initialization vector
 * @param authData Additional data to be authenticated
 * @param q MAC size
 */
export const encryptGCM = (cipherClass: KalynaBase, plainData: Uint8Array, iv: Uint8Array, authData: Uint8Array = new Uint8Array(), q: number = 16): Uint8Array => {
    const enc = ctr(cipherClass, plainData, iv);
    return concatBytes(enc, gmac(cipherClass, authData, enc, q));
}

/**
 * Decrypts data using Galois/Counter Mode (GCM) mode
 * @param cipherClass Initialized cipher class
 * @param plainData Data to be decrypted and authenticated
 * @param iv Initialization vector
 * @param authData Additional data to be authenticated
 * @param q MAC size
 */
export const decryptGCM =  (cipherClass: KalynaBase, encryptedData: Uint8Array, iv: Uint8Array, authData: Uint8Array = new Uint8Array(), q: number = 16): Uint8Array => {
    const enc = encryptedData.slice(0, -q);
    const hC = gmac(cipherClass, authData, enc, q);

    if(!equalBytes(encryptedData.slice(-q), hC)) throw new Error("Invalid MAC");
    return ctr(cipherClass, enc, iv);
}