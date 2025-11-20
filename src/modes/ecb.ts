import { ecb_encrypt, ecb_decrypt } from "@li0ard/gost3413";
import type { KalynaBase } from "../core.js";

/**
 * Encrypts data using Electronic Codebook (ECB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 */
export const encryptECB = (cipherClass: KalynaBase, data: Uint8Array): Uint8Array => {
    return ecb_encrypt(cipherClass.encrypt.bind(cipherClass), cipherClass.blockSize, data);
}

/**
 * Decrypts data using Electronic Codebook (ECB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 */
export const decryptECB = (cipherClass: KalynaBase, data: Uint8Array): Uint8Array => {
    return ecb_decrypt(cipherClass.decrypt.bind(cipherClass), cipherClass.blockSize, data);
}