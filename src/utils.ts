import { bytesToNumberLE, numberToBytesLE, type TArg, type TRet } from "@li0ard/gost3413";

export const bytesToUint64s = (b: TArg<Uint8Array>): TRet<BigUint64Array> => {
    const size = Math.floor(b.length / 8);
    const result = new BigUint64Array(size);
    
    for (let i = 0; i < size; i++) result[i] = bytesToNumberLE(b.slice(i * 8, i * 8 + 8));
    return result;
}

export const uint64sToBytes = (w: TArg<BigUint64Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(w.length * 8);
    for (let i = 0; i < w.length; i++) result.set(numberToBytesLE(w[i], 8), i * 8);
    return result;
}

export const swap_block = (k: TArg<BigUint64Array>, N: number) => {
    if (N <= 1) return;
    const t = k[0];
    for (let i = 0; i < N - 1; i++) k[i] = k[i + 1];
    k[N - 1] = t;
}

export const gf2mMul = (blockSize: number, a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    let temp = new Uint8Array(a);
    let result = new Uint8Array(blockSize);
    
    let reductionBytes = [[0x87], [0x25, 0x04], [0x25, 0x01]][Math.log2(blockSize) - 4];
    
    for (let i = 0; i < blockSize * 8; i++) {
        const byteIndex = Math.floor(i / 8);
        const bitIndex = i % 8;
        if (byteIndex < b.length && (b[byteIndex] & (1 << bitIndex))) for (let j = 0; j < blockSize; j++) result[j] ^= temp[j];
      
        let carry = 0;
        for (let j = 0; j < blockSize; j++) {
            const nextCarry = (temp[j] & 0x80) ? 1 : 0;
            temp[j] = ((temp[j] << 1) & 0xFF) | carry;
            carry = nextCarry;
        }
      
        if (carry) {
            for (let j = 0; j < reductionBytes.length; j++) if (j < blockSize) temp[j] ^= reductionBytes[j];
        }
    }
    
    return result;
}