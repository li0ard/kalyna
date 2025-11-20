import type { KalynaBase } from "../core.js";
import { gf2mMul, numberToBytesLE } from "../utils.js";

/**
 * Encrypts data using XEX Tweakable Block Ciphertext Stealing (XTS) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be encrypted
 * @param iv Initialization vector
 */
export const encryptXTS = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    const block_len = cipherClass.blockSize;
    const plain_size = data.length;
    const padded_len = block_len - (plain_size % block_len);
    const total_len = plain_size + padded_len;
    const plain_data = new Uint8Array(total_len);
    plain_data.set(data);

    let gamma = cipherClass.encrypt(iv);
    if (gamma.length < block_len) {
        const expanded = new Uint8Array(block_len);
        expanded.set(gamma);
        gamma = expanded;
    }

    const two = numberToBytesLE(2, block_len);
    const loop_len = (padded_len === block_len) ? plain_size : (plain_size - block_len);
    let i = 0;

    for (; i < loop_len; i += block_len) {
        gamma = gf2mMul(block_len, gamma, two);
        for (let j = 0; j < block_len; j++) plain_data[i + j] ^= gamma[j];

        const encryptedBlock = cipherClass.encrypt(plain_data.subarray(i, i + block_len));
        for (let j = 0; j < block_len; j++) plain_data[i + j] = encryptedBlock[j];
        for (let j = 0; j < block_len; j++) plain_data[i + j] ^= gamma[j];
    }

    if (padded_len !== block_len) {
        const original_i = i;
        const paddingSourcePos = original_i - block_len + (plain_size % block_len);
        const paddingDestPos = original_i + (plain_size % block_len);
        plain_data.set(plain_data.subarray(paddingSourcePos, paddingSourcePos + padded_len), paddingDestPos);

        gamma = gf2mMul(block_len, gamma, two);
        for (let j = 0; j < block_len; j++) plain_data[original_i + j] ^= gamma[j];
        const encryptedLastBlock = cipherClass.encrypt(plain_data.subarray(original_i, original_i + block_len));
        for (let j = 0; j < block_len; j++) plain_data[original_i + j] = encryptedLastBlock[j] ^ gamma[j];

        const prevBlockStart = original_i - block_len;
        if (prevBlockStart >= 0) {
            const tempBlock = new Uint8Array(block_len);
            tempBlock.set(plain_data.subarray(prevBlockStart, prevBlockStart + block_len));
            plain_data.set(plain_data.subarray(original_i, original_i + block_len), prevBlockStart);
            plain_data.set(tempBlock.subarray(0, block_len - padded_len), original_i);
        }
    }

    return plain_data.slice(0, plain_size);
}

/**
 * Decrypts data using XEX Tweakable Block Ciphertext Stealing (XTS) mode
 * @param cipherClass Initialized cipher class
 * @param data Data to be decrypted
 * @param iv Initialization vector
 */
export const decryptXTS = (cipherClass: KalynaBase, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    const block_len = cipherClass.blockSize;
    const plain_size = data.length;
    const padded_len = block_len - (plain_size % block_len);
    const total_len = plain_size + padded_len;
    const plain_data = new Uint8Array(total_len);
    plain_data.set(data);

    let gamma = cipherClass.encrypt(iv);
    if (gamma.length < block_len) {
        const expanded = new Uint8Array(block_len);
        expanded.set(gamma);
        gamma = expanded;
    }

    const two = numberToBytesLE(2, block_len);
    const loop_num = (padded_len === block_len) ? plain_size : (plain_size < 2 * block_len ? 0 : plain_size - 2 * block_len);

    let i = 0;
    for (; i < loop_num; i += block_len) {
        gamma = gf2mMul(block_len, gamma, two);
        for (let j = 0; j < block_len; j++) plain_data[i + j] ^= gamma[j];

        const decryptedBlock = cipherClass.decrypt(plain_data.subarray(i, i + block_len));
        for (let j = 0; j < block_len; j++) plain_data[i + j] = decryptedBlock[j];
        for (let j = 0; j < block_len; j++) plain_data[i + j] ^= gamma[j];
    }

    if (padded_len !== block_len) {
        gamma = gf2mMul(block_len, gamma, two);
        const gamma2 = gf2mMul(block_len, gamma, two);
        for (let j = 0; j < block_len; j++) plain_data[i + j] ^= gamma2[j];

        const decryptedLastBlock = cipherClass.decrypt(plain_data.subarray(i, i + block_len));
        for (let j = 0; j < block_len; j++) plain_data[i + j] = decryptedLastBlock[j] ^ gamma2[j];

        i += block_len;
        i += plain_size % block_len;
        plain_data.set(plain_data.subarray(i - block_len, i - block_len + padded_len), i);
        i -= plain_size % block_len;

        for (let j = 0; j < block_len; j++) plain_data[i + j] ^= gamma[j];
        const decryptedPrevBlock = cipherClass.decrypt(plain_data.subarray(i, i + block_len));
        for (let j = 0; j < block_len; j++) plain_data[i + j] = decryptedPrevBlock[j] ^ gamma[j];

        const prevBlockStart = i - block_len;
        if (prevBlockStart >= 0) {
            const tempBlock = new Uint8Array(block_len);
            tempBlock.set(plain_data.subarray(prevBlockStart, prevBlockStart + block_len));
            plain_data.set(plain_data.subarray(i, i + block_len), prevBlockStart);
            plain_data.set(tempBlock.subarray(0, block_len - padded_len), i);
        }
    }

    return plain_data.slice(0, plain_size);
}