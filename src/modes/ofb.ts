import { ofb as ofb_, type TArg, type TRet } from "@li0ard/gost3413";
import type { KalynaBase } from "../core.js";

/**
 * Proceed data using the Output Feedback (OFB) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted/decrypted
 * @param iv Initialization vector
 */
export const ofb = (cipherClass: KalynaBase, data: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> =>
    ofb_(cipherClass.encrypt.bind(cipherClass), cipherClass.blockSize, data, iv);