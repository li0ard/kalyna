import { concatBytes, equalBytes, type TArg, type TRet } from "@li0ard/gost3413/dist/utils.js";
import { ctr } from "../index.js";
import type { KalynaBase } from "../core.js";

const ccm_mac = (
    cipherClass: KalynaBase,
    iv: TArg<Uint8Array>,
    authData: TArg<Uint8Array>,
    plainData: TArg<Uint8Array>,
    q: number = 16,
    Nb: number = 4
): TRet<Uint8Array> => {
    const blockSize = cipherClass.blockSize;
    if (blockSize < Nb + 1) throw new Error('blockSize must be >= Nb + 1');

    const tmp = blockSize - Nb - 1;
    const G1 = new Uint8Array(blockSize);
    const G2 = new Uint8Array(blockSize);
    const B = new Uint8Array(blockSize);
    G1.set(iv.slice(0, tmp), 0);
    G1[tmp] = plainData.length & 0xFF;
    if (plainData.length > 0) G1[blockSize - 1] = 1 << 7;
    else G1[blockSize - 1] = 0;

    switch (q) {
        case 8:
            G1[blockSize - 1] |= 2 << 4;
            break;
        case 16:
            G1[blockSize - 1] |= 3 << 4;
            break;
        case 32:
            G1[blockSize - 1] |= 4 << 4;
            break;
        case 48:
            G1[blockSize - 1] |= 5 << 4;
            break;
        case 64:
            G1[blockSize - 1] |= 6 << 4;
            break;
        default:
            throw new Error('Invalid q value');
    }

    G1[blockSize - 1] |= (Nb - 1);
    G2[0] = authData.length & 0xFF;

    const tmp2 = authData.length % blockSize;
    const hLength = blockSize + (blockSize - tmp2) + authData.length;
    const h = new Uint8Array(hLength);
    h.set(G1, 0);
    h.set(G2.slice(0, blockSize - tmp2), blockSize);
    h.set(authData, blockSize + (blockSize - tmp2));

    for (let i = 0; i < hLength; i += blockSize) {
        const chunk = h.slice(i, i + blockSize);
        for (let j = 0; j < blockSize; j++) B[j] ^= chunk[j];
        const encrypted = cipherClass.encrypt(B);
        B.set(encrypted);
    }

    let paddedPlainData = plainData;
    if (plainData.length % blockSize !== 0) {
        const paddingLength = blockSize - (plainData.length % blockSize);
        paddedPlainData = new Uint8Array(plainData.length + paddingLength);
        paddedPlainData.set(plainData);
        paddedPlainData[plainData.length] = 0x80;
    }

    for (let i = 0; i < paddedPlainData.length; i += blockSize) {
        const chunk = paddedPlainData.slice(i, i + blockSize);
        for (let j = 0; j < blockSize; j++) B[j] ^= chunk[j];
        const encrypted = cipherClass.encrypt(B);
        B.set(encrypted);
    }

    return B.slice(0, q);
}

/**
 * Encrypts data using Counter with Cipher Block Chaining-Message Authentication Code (CCM) mode
 * @param cipherClass Initialized cipher class
 * @param plainData Data to be encrypted and authenticated
 * @param iv Initialization vector
 * @param authData Additional data to be authenticated
 * @param q MAC size
 * @param Nb Param `Nb`
 */
export const encryptCCM = (
    cipherClass: KalynaBase,
    plainData: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    authData: TArg<Uint8Array> = new Uint8Array(),
    q: number = 16,
    Nb: number = 4
): TRet<Uint8Array> => {
    const h = ccm_mac(cipherClass, iv, authData, plainData, q, Nb);
    return ctr(cipherClass, concatBytes(plainData, h), iv);
}

/**
 * Decrypts data using Counter with Cipher Block Chaining-Message Authentication Code (CCM) mode
 * @param cipherClass Initialized cipher class
 * @param encryptedData Data to be decrypted and authenticated
 * @param iv Initialization vector
 * @param authData Additional data to be authenticated
 * @param q MAC size
 * @param Nb Param `Nb`
 */
export const decryptCCM = (
    cipherClass: KalynaBase,
    encryptedData: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    authData: TArg<Uint8Array> = new Uint8Array(),
    q: number = 16,
    Nb: number = 4
): TRet<Uint8Array> => {
    const raw = ctr(cipherClass, encryptedData, iv);
    const pt = raw.slice(0, -q);
    const hC = ccm_mac(cipherClass, iv, authData, pt, q, Nb);

    if(!equalBytes(raw.slice(-q), hC)) throw new Error("Invalid MAC");
    return pt;
}