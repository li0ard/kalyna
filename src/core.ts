import type { TArg, TRet } from "@li0ard/gost3413";
import { IS, IT, KUPYNA_T, S } from "./const.js";
import { bytesToUint64s, swap_block, uint64sToBytes } from "./utils.js";

/** Kalyna abstract class */
export abstract class KalynaBase {
    /** Round keys for encryption */
    public erk!: TArg<BigUint64Array>;
    /** Rounds keys for decryption */
    public drk!: TArg<BigUint64Array>;
    /** Block size */
    public readonly blockSize: number;
    /** Key size */
    public readonly keySize: number;

    private readonly numRounds: number;
    private readonly glOffset: number;
    private wordOffsets: number[];

    /** Kalyna abstract class */
    constructor(key: TArg<Uint8Array>, public readonly N: number, isDouble: boolean = false) {
        if(N < 2 || (N & (N - 1)) !== 0) throw new Error("N must be power of 2 and >= 2");
        this.blockSize = N << 3;
        this.keySize = this.blockSize;
        if(isDouble) this.keySize *= 2;
        if (key.length !== this.keySize) throw new Error("Invalid key length");

        this.wordOffsets = Array.from({length: 8}, (_, j) => Math.floor(j * this.N / 8));
        const X = 6 + 4 * Math.log2(N) + (isDouble ? 4 : 0);
        this.numRounds = X - (N > 2 || isDouble ? 1 : 0);
        this.glOffset = X * N;
        this.expandKey(key);
    }

    private expandKey(key: TArg<Uint8Array>) {
        const log2N = Math.log2(this.N),
            // For 128/256 and 256/512 versions
            isDoubleKey = (this.keySize === this.blockSize * 2),
            R = isDoubleKey ? (6 + 2 * log2N) : (4 + 2 * log2N),
            rk = new BigUint64Array(R * this.N * 2),
            ks = new BigUint64Array(this.N),
            ksc = new BigUint64Array(this.N),
            t1 = new BigUint64Array(this.N),
            t2 = new BigUint64Array(this.N);
        t1[0] = isDoubleKey ? BigInt(2 * this.N + 2 * log2N + 1) : BigInt(2 * this.N + 1);

        const keys = bytesToUint64s(key);
        let k = new BigUint64Array(isDoubleKey ? this.N * 2 : this.N);

        if (isDoubleKey) {
            const ka = keys.slice(0, this.N);
            this.addkey(t1, t2, ka);
            this.G(t2, t1, keys.slice(this.N));
            this.GL(t1, t2, ka);
            this.G0(t2, ks);
            k.set(keys);
        } else {
            k.set(keys.slice(0, this.N));
            this.addkey(t1, t2, keys);
            this.G(t2, t1, keys);
            this.GL(t1, t2, keys);
            this.G0(t2, ks);
        }

        let constant = 0x0001000100010001n;
    
        for (let i = 0; i < R; i++) {
            const offset = i * (this.N * 2);
        
            if (i > 0) {
                if (!isDoubleKey) swap_block(k, this.N);
                else if (i % 2 === 0) swap_block(k, this.N * 2);
            }
        
            const keySource = isDoubleKey ? (i % 2 === 0 ? k.subarray(0, this.N) : k.subarray(this.N)) : k;
            this.add_constant(ks, ksc, constant);
            this.addkey(keySource, t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset), ksc);
        
            if (i < R - 1) this.makeOddKey(rk.subarray(offset), rk.subarray(offset + this.N));
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = ((R * 2 - 3) * this.N); i > 0; i -= this.N) this.IMC(rk.subarray(i));
        this.drk = rk.slice();
    }

    private makeOddKey(evenkey: TArg<BigUint64Array>, oddkey: TArg<BigUint64Array>) {
        const offset = 2 * this.N + 3;
        const evenkeys = uint64sToBytes(evenkey);
        const oddkeys = uint64sToBytes(oddkey);

        oddkeys.set(evenkeys.slice(offset, this.blockSize));
        oddkeys.set(evenkeys.slice(0, offset), (this.blockSize - offset));
        oddkey.set(bytesToUint64s(oddkeys));
    }

    private addkey(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) y[i] = x[i] + k[i];
    }

    private subkey(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) y[i] = x[i] - k[i];
    }

    private add_constant(src: TArg<BigUint64Array>, dst: TArg<BigUint64Array>, constant: bigint) {
        for(let i = 0; i < this.N; i++) dst[i] = src[i] + constant;
    }

    private byte(a: bigint): number { return Number(a & 0xFFn); }

    private G0(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) {
            y[i] = 0n;
            for (let j = 0; j < 8; j++) {
                y[i] ^= KUPYNA_T[j][this.byte(x[(i - this.wordOffsets[j] + this.N) % this.N] >> BigInt(j << 3))];
            }
        }
    }

    private G(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) {
            y[i] = k[i];
            for (let j = 0; j < 8; j++) {
                y[i] ^= KUPYNA_T[j][this.byte(x[(i - this.wordOffsets[j] + this.N) % this.N] >> BigInt(j << 3))];
            }
        }
    }

    private GL(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) {
            let temp = 0n;
            for (let j = 0; j < 8; j++) {
                temp ^= KUPYNA_T[j][this.byte(x[(i - this.wordOffsets[j] + this.N) % this.N] >> BigInt(j << 3))];
            }
            y[i] = k[i] + temp;
        }
    }

    private IMC(x: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) {
            const v = x[i];
            x[i] = IT[0][S[0][this.byte(v)]] ^
                IT[1][S[1][this.byte(v >> 8n)]] ^
                IT[2][S[2][this.byte(v >> 16n)]] ^
                IT[3][S[3][this.byte(v >> 24n)]] ^
                IT[4][S[0][this.byte(v >> 32n)]] ^
                IT[5][S[1][this.byte(v >> 40n)]] ^
                IT[6][S[2][this.byte(v >> 48n)]] ^
                IT[7][S[3][this.byte(v >> 56n)]];
        }
    }

    private IG(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) {
            let result = k[i];
            for (let j = 0; j < 8; j++) {
                result ^= IT[j][this.byte(x[(i + this.wordOffsets[j]) % this.N] >> BigInt(j << 3))];
            }
            y[i] = result;
        }
    }

    private IGL(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) {
            let result = 0n;
            for (let j = 0; j < 8; j++) {
                const shift = BigInt(j << 3);
                result ^= BigInt(IS[j % 4][this.byte(x[(i + this.wordOffsets[j]) % this.N] >> shift)]) << shift;
            }
            y[i] = result - k[i];
        }
    }

    /**
     * Encrypt data
     * @param in_ Data to be encrypted
     */
    public encrypt(in_: TArg<Uint8Array>): TRet<Uint8Array> {
        if(in_.length != this.blockSize) throw new Error(`Incorrect length (need - ${this.blockSize}, got - ${in_.length})`);
        const t1 = new BigUint64Array(this.N);
        const t2 = new BigUint64Array(this.N);
        const ins = bytesToUint64s(in_);
        const rk = this.erk.slice();

        this.addkey(ins, t1, rk);

        for (let i = 0; i < this.numRounds; i++) {
            const roundKey = rk.subarray(this.N + i * this.N);
            if (i % 2 === 0) this.G(t1, t2, roundKey);
            else this.G(t2, t1, roundKey);
        }

        this.GL(t2, t1, rk.subarray(this.glOffset));
        return uint64sToBytes(t1);
    }

    /**
     * Decrypt data
     * @param in_ Data to be decrypted
     */
    public decrypt(in_: TArg<Uint8Array>): TRet<Uint8Array> {
        if(in_.length != this.blockSize) throw new Error(`Incorrect length (need - ${this.blockSize}, got - ${in_.length})`);
        const t1 = new BigUint64Array(this.N);
        const t2 = new BigUint64Array(this.N);
        const ins = bytesToUint64s(in_);
        const rk = this.drk.slice();

        this.subkey(ins, t1, rk.subarray(this.glOffset));
        this.IMC(t1);

        for (let i = 0; i < this.numRounds; i++) {
            const roundKey = rk.subarray(this.glOffset - this.N - i * this.N);
            if (i % 2 === 0) this.IG(t1, t2, roundKey);
            else this.IG(t2, t1, roundKey);
        }

        this.IGL(t2, t1, rk);
        return uint64sToBytes(t1);
    }
}