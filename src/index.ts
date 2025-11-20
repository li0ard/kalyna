import { KalynaBase } from "./core.js";

/** Kalyna 128 bit version */
export class Kalyna128 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 2); }
}
/** Kalyna 128/256 bit version */
export class Kalyna128_256 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 2, true); }
}

/** Kalyna 256 bit version */
export class Kalyna256 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 4); }
}
/** Kalyna 256/512 bit version */
export class Kalyna256_512 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 4, true); }
}

/** Kalyna 512 bit version */
export class Kalyna512 extends KalynaBase {
    constructor(key: Uint8Array) { super(key, 8); }
}

export * from "./padding.js";
export * from "./modes/ecb.js";
export * from "./modes/cbc.js";
export * from "./modes/ofb.js";
export * from "./modes/ctr.js";
export * from "./modes/mac.js";
export * from "./modes/cfb.js";
export * from "./modes/ccm.js";
export * from "./modes/gcm.js";
export * from "./modes/kw.js";
export * from "./modes/xts.js";