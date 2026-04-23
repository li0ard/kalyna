import { concatBytes, xor, type TArg, type TRet } from "@li0ard/gost3413/dist/utils.js";
import type { KalynaBase } from "../core.js";

const incrementCounterAt = (ctr: TArg<Uint8Array>, pos: number) => {
    let j = pos;
    while (j < ctr.length) if (++ctr[j++] != 0) break;
}

/**
 * Proceed data using the Counter (CTR) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted/decrypted
 * @param iv Initialization vector
 */
export const ctr = (cipherClass: KalynaBase, data: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> => {
    if (iv.length !== cipherClass.blockSize) throw new Error("Invalid IV size");

    const keystreamBlocks: Uint8Array[] = [];
    const ctr = cipherClass.encrypt(iv);
    for (let i = 0; i < Math.ceil(data.length / cipherClass.blockSize); i++) {
        incrementCounterAt(ctr, 0);
        keystreamBlocks.push(cipherClass.encrypt(ctr));
    }

    return xor(concatBytes(...keystreamBlocks), data);
}