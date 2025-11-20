import { ofb as ofb_ } from "@li0ard/gost3413";
import type { KalynaBase } from "../core.js";

/**
 * Proceed data using the Output Feedback (OFB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted/decrypted
 * @param iv Initialization vector
 */
export const ofb = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    return ofb_(cipherClass.encrypt.bind(cipherClass), cipherClass.blockSize, data, iv);
}
