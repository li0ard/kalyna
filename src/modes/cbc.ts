import { cbc_encrypt, cbc_decrypt, type TArg, type TRet } from "@li0ard/gost3413";
import type { KalynaBase } from "../core.js";

/**
 * Encrypts data using Cipher Block Chaining (CBC) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 * @param iv Initialization vector
 */
export const encryptCBC = (
    cipherClass: KalynaBase,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> =>
    cbc_encrypt(cipherClass.encrypt.bind(cipherClass), cipherClass.blockSize, data, iv);

/**
 * Decrypts data using Cipher Block Chaining (CBC) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be decrypted
 * @param iv Initialization vector
 */
export const decryptCBC = (
    cipherClass: KalynaBase,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> =>
    cbc_decrypt(cipherClass.decrypt.bind(cipherClass), cipherClass.blockSize, data, iv);
