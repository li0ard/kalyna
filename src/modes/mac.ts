import { xor } from "@li0ard/gost3413/dist/utils.js";
import type { KalynaBase } from "../core.js";
import { pad } from "../padding.js";

/**
 * Compute CMAC
 * @param cipherClass Initialized cipher class
 * @param in_ Data to be authenticated
 */
export const cmac = (cipherClass: KalynaBase, data: Uint8Array, q: number = 16): Uint8Array => {
    const zeroBlock = new Uint8Array(cipherClass.blockSize);

    if(data.length % cipherClass.blockSize !== 0) {
        data = pad(data, cipherClass.blockSize);
        zeroBlock[0] = 1;
    }

    const Kd = cipherClass.encrypt(zeroBlock);
    let c: Uint8Array = new Uint8Array(cipherClass.blockSize);
    const numBlocks = data.length / cipherClass.blockSize;

    for (let i = 0; i < numBlocks - 1; i++) {
        const blockStart = i * cipherClass.blockSize;        
        c = cipherClass.encrypt(xor(c, data.subarray(blockStart, blockStart + cipherClass.blockSize)));
    }

    const lastBlockStart = (numBlocks - 1) * cipherClass.blockSize;
    c = cipherClass.encrypt(xor(xor(c, data.subarray(lastBlockStart, lastBlockStart + cipherClass.blockSize)), Kd));

    return c.slice(0, q);
}