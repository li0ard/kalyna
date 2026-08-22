<p align="center">
    <b>@li0ard/kalyna</b><br>
    <b>Kalyna (DSTU 7624:2014) cipher implementation in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/kalyna">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/kalyna/actions/workflows/test.yml"><img src="https://github.com/li0ard/kalyna/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/kalyna/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/kalyna" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/kalyna"><img src="https://img.shields.io/npm/v/@li0ard/kalyna" /></a>
    <a href="https://jsr.io/@li0ard/kalyna"><img src="https://jsr.io/badges/@li0ard/kalyna" /></a>
    <br>
    <hr>
</p>

> [!IMPORTANT]  
> This repository is archived. All DSTU implementations moved to [`@li0ard/dstu`](https://github.com/li0ard/dstu)

## Installation

```bash
# from NPM
npm i @li0ard/kalyna

# from JSR
bunx jsr i @li0ard/kalyna
```

## Supported modes
- [x] Electronic Codebook (ECB)
- [x] Cipher Block Chaining (CBC)
- [x] Output Feedback (OFB)
- [x] Counter (CTR)
- [x] Cipher Feedback (CFB)
- [x] Cipher-based Message Authentication Code (CMAC/OMAC)
- [x] Cipher Block Chaining-Message Authentication Code (CCM)
- [x] Galois Message Authentication Code (GMAC)
- [x] Galois/Counter Mode (GCM)
- [x] Key wrapping (KW)
- [x] XEX Tweakable Block Ciphertext Stealing (XTS)

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with [DSTU 7624:2014](https://online.budstandart.com/upload/documents/121/109736_2.pdf) standard
- Supports Bun, Node.js, Deno, Browsers

## Examples
### ECB mode
```ts
import { Kalyna128, encryptECB, decryptECB } from "@li0ard/kalyna";

const cipher = new Kalyna128(hexToBytes("000102030405060708090A0B0C0D0E0F"));
const ct = hexToBytes("81BF1C7D779BAC20E1C9EA39B4D2AD06");
const pt = hexToBytes("101112131415161718191A1B1C1D1E1F");

console.log(encryptECB(cipher, pt));
console.log(decryptECB(cipher, ct));
```

### CBC mode
```ts
import { Kalyna128, encryptCBC, decryptCBC } from "@li0ard/kalyna";

const cipher = new Kalyna128(hexToBytes("000102030405060708090A0B0C0D0E0F"));
const iv = hexToBytes("101112131415161718191A1B1C1D1E1F");
const ct = hexToBytes("a73625d7be994e85469a9faabcedaab6dbc5f65dd77bb35e06bd7d1d8eafc8624d6cb31ce189c82b8979f2936de9bf14");
const pt = hexToBytes("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");

console.log(encryptCBC(cipher, pt, iv));
console.log(decryptCBC(cipher, ct, iv));
```
