/**
 * @keepass-web/chacha20
 *
 * ChaCha20 (RFC 8439) and Salsa20 (D. J. Bernstein) stream ciphers.
 *
 * Scope is intentionally limited to the raw stream ciphers. Poly1305 and the
 * ChaCha20-Poly1305 AEAD construction from RFC 8439 are NOT implemented: KDBX
 * authenticates with HMAC-SHA256, so the AEAD is not needed by keepass-web.
 *
 * Both ciphers expose three layers:
 *   - a pure 64-byte block function (`chacha20Block` / `salsa20Block`);
 *   - a one-shot helper (`chacha20` / `salsa20`) for whole buffers;
 *   - a stateful class (`ChaCha20` / `Salsa20`) whose `encrypt`/`decrypt`
 *     consume a single continuous keystream across successive calls. The
 *     stateful form is what KDBX inner-stream (protected-field) processing
 *     needs, since protected values are XORed against one running keystream in
 *     document order.
 */

/** A 32-bit unsigned word. */
type Word = number;

/** Result of a quarter round: four updated 32-bit words. */
type QuarterRound = [Word, Word, Word, Word];

const KEY_BYTES = 32;
const BLOCK_BYTES = 64;
const CHACHA_NONCE_BYTES = 12;
const SALSA_NONCE_BYTES = 8;

/** "expand 32-byte k" as four little-endian 32-bit words. */
const SIGMA: readonly [Word, Word, Word, Word] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/** Left-rotate a 32-bit word by `n` bits. */
const rotl = (x: Word, n: number): Word => ((x << n) | (x >>> (32 - n))) >>> 0;

function assertLength(bytes: Uint8Array, expected: number, name: string): void {
  if (bytes.length !== expected) {
    throw new RangeError(`${name} must be ${expected} bytes, got ${bytes.length}`);
  }
}

/** The ChaCha20 quarter round (RFC 8439 §2.1). */
function chachaQuarterRound(a0: Word, b0: Word, c0: Word, d0: Word): QuarterRound {
  let a = a0;
  let b = b0;
  let c = c0;
  let d = d0;
  a = (a + b) >>> 0;
  d = rotl(d ^ a, 16);
  c = (c + d) >>> 0;
  b = rotl(b ^ c, 12);
  a = (a + b) >>> 0;
  d = rotl(d ^ a, 8);
  c = (c + d) >>> 0;
  b = rotl(b ^ c, 7);
  return [a, b, c, d];
}

/** The Salsa20 quarter round (Bernstein, "Salsa20 specification"). */
function salsaQuarterRound(y0: Word, y1: Word, y2: Word, y3: Word): QuarterRound {
  let a = y0;
  let b = y1;
  let c = y2;
  let d = y3;
  b = (b ^ rotl((a + d) >>> 0, 7)) >>> 0;
  c = (c ^ rotl((b + a) >>> 0, 9)) >>> 0;
  d = (d ^ rotl((c + b) >>> 0, 13)) >>> 0;
  a = (a ^ rotl((d + c) >>> 0, 18)) >>> 0;
  return [a, b, c, d];
}

/**
 * Generate one 64-byte ChaCha20 keystream block (RFC 8439 §2.3).
 *
 * @param key 32-byte key.
 * @param nonce 12-byte nonce.
 * @param counter 32-bit block counter (taken modulo 2^32).
 */
export function chacha20Block(key: Uint8Array, nonce: Uint8Array, counter: number): Uint8Array {
  assertLength(key, KEY_BYTES, 'key');
  assertLength(nonce, CHACHA_NONCE_BYTES, 'nonce');

  const k = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const n = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);

  const s0 = SIGMA[0];
  const s1 = SIGMA[1];
  const s2 = SIGMA[2];
  const s3 = SIGMA[3];
  const s4 = k.getUint32(0, true);
  const s5 = k.getUint32(4, true);
  const s6 = k.getUint32(8, true);
  const s7 = k.getUint32(12, true);
  const s8 = k.getUint32(16, true);
  const s9 = k.getUint32(20, true);
  const s10 = k.getUint32(24, true);
  const s11 = k.getUint32(28, true);
  const s12 = counter >>> 0;
  const s13 = n.getUint32(0, true);
  const s14 = n.getUint32(4, true);
  const s15 = n.getUint32(8, true);

  let x0 = s0;
  let x1 = s1;
  let x2 = s2;
  let x3 = s3;
  let x4 = s4;
  let x5 = s5;
  let x6 = s6;
  let x7 = s7;
  let x8 = s8;
  let x9 = s9;
  let x10 = s10;
  let x11 = s11;
  let x12 = s12;
  let x13 = s13;
  let x14 = s14;
  let x15 = s15;

  // 20 rounds = 10 iterations of (column rounds + diagonal rounds).
  for (let i = 0; i < 10; i += 1) {
    [x0, x4, x8, x12] = chachaQuarterRound(x0, x4, x8, x12);
    [x1, x5, x9, x13] = chachaQuarterRound(x1, x5, x9, x13);
    [x2, x6, x10, x14] = chachaQuarterRound(x2, x6, x10, x14);
    [x3, x7, x11, x15] = chachaQuarterRound(x3, x7, x11, x15);
    [x0, x5, x10, x15] = chachaQuarterRound(x0, x5, x10, x15);
    [x1, x6, x11, x12] = chachaQuarterRound(x1, x6, x11, x12);
    [x2, x7, x8, x13] = chachaQuarterRound(x2, x7, x8, x13);
    [x3, x4, x9, x14] = chachaQuarterRound(x3, x4, x9, x14);
  }

  const out = new Uint8Array(BLOCK_BYTES);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, (x0 + s0) >>> 0, true);
  dv.setUint32(4, (x1 + s1) >>> 0, true);
  dv.setUint32(8, (x2 + s2) >>> 0, true);
  dv.setUint32(12, (x3 + s3) >>> 0, true);
  dv.setUint32(16, (x4 + s4) >>> 0, true);
  dv.setUint32(20, (x5 + s5) >>> 0, true);
  dv.setUint32(24, (x6 + s6) >>> 0, true);
  dv.setUint32(28, (x7 + s7) >>> 0, true);
  dv.setUint32(32, (x8 + s8) >>> 0, true);
  dv.setUint32(36, (x9 + s9) >>> 0, true);
  dv.setUint32(40, (x10 + s10) >>> 0, true);
  dv.setUint32(44, (x11 + s11) >>> 0, true);
  dv.setUint32(48, (x12 + s12) >>> 0, true);
  dv.setUint32(52, (x13 + s13) >>> 0, true);
  dv.setUint32(56, (x14 + s14) >>> 0, true);
  dv.setUint32(60, (x15 + s15) >>> 0, true);
  return out;
}

/**
 * Generate one 64-byte Salsa20 keystream block (Bernstein spec).
 *
 * @param key 32-byte key.
 * @param nonce 8-byte nonce.
 * @param counter 64-bit block counter (as a JS number; exact below 2^53).
 */
export function salsa20Block(key: Uint8Array, nonce: Uint8Array, counter: number): Uint8Array {
  assertLength(key, KEY_BYTES, 'key');
  assertLength(nonce, SALSA_NONCE_BYTES, 'nonce');

  const k = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const n = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  const counterLow = counter >>> 0;
  const counterHigh = Math.floor(counter / 0x1_0000_0000) >>> 0;

  const s0 = SIGMA[0];
  const s1 = k.getUint32(0, true);
  const s2 = k.getUint32(4, true);
  const s3 = k.getUint32(8, true);
  const s4 = k.getUint32(12, true);
  const s5 = SIGMA[1];
  const s6 = n.getUint32(0, true);
  const s7 = n.getUint32(4, true);
  const s8 = counterLow;
  const s9 = counterHigh;
  const s10 = SIGMA[2];
  const s11 = k.getUint32(16, true);
  const s12 = k.getUint32(20, true);
  const s13 = k.getUint32(24, true);
  const s14 = k.getUint32(28, true);
  const s15 = SIGMA[3];

  let x0 = s0;
  let x1 = s1;
  let x2 = s2;
  let x3 = s3;
  let x4 = s4;
  let x5 = s5;
  let x6 = s6;
  let x7 = s7;
  let x8 = s8;
  let x9 = s9;
  let x10 = s10;
  let x11 = s11;
  let x12 = s12;
  let x13 = s13;
  let x14 = s14;
  let x15 = s15;

  // 20 rounds = 10 double rounds of (column round, then row round).
  for (let i = 0; i < 10; i += 1) {
    // Column round.
    [x0, x4, x8, x12] = salsaQuarterRound(x0, x4, x8, x12);
    [x5, x9, x13, x1] = salsaQuarterRound(x5, x9, x13, x1);
    [x10, x14, x2, x6] = salsaQuarterRound(x10, x14, x2, x6);
    [x15, x3, x7, x11] = salsaQuarterRound(x15, x3, x7, x11);
    // Row round.
    [x0, x1, x2, x3] = salsaQuarterRound(x0, x1, x2, x3);
    [x5, x6, x7, x4] = salsaQuarterRound(x5, x6, x7, x4);
    [x10, x11, x8, x9] = salsaQuarterRound(x10, x11, x8, x9);
    [x15, x12, x13, x14] = salsaQuarterRound(x15, x12, x13, x14);
  }

  const out = new Uint8Array(BLOCK_BYTES);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, (x0 + s0) >>> 0, true);
  dv.setUint32(4, (x1 + s1) >>> 0, true);
  dv.setUint32(8, (x2 + s2) >>> 0, true);
  dv.setUint32(12, (x3 + s3) >>> 0, true);
  dv.setUint32(16, (x4 + s4) >>> 0, true);
  dv.setUint32(20, (x5 + s5) >>> 0, true);
  dv.setUint32(24, (x6 + s6) >>> 0, true);
  dv.setUint32(28, (x7 + s7) >>> 0, true);
  dv.setUint32(32, (x8 + s8) >>> 0, true);
  dv.setUint32(36, (x9 + s9) >>> 0, true);
  dv.setUint32(40, (x10 + s10) >>> 0, true);
  dv.setUint32(44, (x11 + s11) >>> 0, true);
  dv.setUint32(48, (x12 + s12) >>> 0, true);
  dv.setUint32(52, (x13 + s13) >>> 0, true);
  dv.setUint32(56, (x14 + s14) >>> 0, true);
  dv.setUint32(60, (x15 + s15) >>> 0, true);
  return out;
}

/** Drives a block function as a continuous, stateful keystream. */
class KeystreamCipher {
  #block: (counter: number) => Uint8Array;
  #counter: number;
  #buffer: Uint8Array;
  #position: number;

  constructor(block: (counter: number) => Uint8Array, counter: number) {
    this.#block = block;
    this.#counter = counter;
    this.#buffer = new Uint8Array(BLOCK_BYTES);
    this.#position = BLOCK_BYTES;
  }

  /** XOR `data` with the next keystream bytes, continuing across calls. */
  process(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    let i = 0;
    for (const byte of data) {
      if (this.#position === BLOCK_BYTES) {
        this.#buffer = this.#block(this.#counter);
        this.#counter += 1;
        this.#position = 0;
      }
      out[i] = byte ^ (this.#buffer[this.#position] ?? 0);
      this.#position += 1;
      i += 1;
    }
    return out;
  }
}

/**
 * Stateful ChaCha20 (RFC 8439) cipher.
 *
 * `encrypt` and `decrypt` are identical XOR operations that share one
 * continuous keystream across successive calls — the form needed for the KDBX
 * inner random stream and for chunked payload (de)cryption.
 */
export class ChaCha20 {
  #cipher: KeystreamCipher;

  /**
   * @param key 32-byte key.
   * @param nonce 12-byte nonce.
   * @param counter Initial 32-bit block counter (default 0).
   */
  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0) {
    assertLength(key, KEY_BYTES, 'key');
    assertLength(nonce, CHACHA_NONCE_BYTES, 'nonce');
    const k = key.slice();
    const n = nonce.slice();
    this.#cipher = new KeystreamCipher((c) => chacha20Block(k, n, c), counter >>> 0);
  }

  encrypt(data: Uint8Array): Uint8Array {
    return this.#cipher.process(data);
  }

  decrypt(data: Uint8Array): Uint8Array {
    return this.#cipher.process(data);
  }
}

/**
 * Stateful Salsa20 (Bernstein) cipher.
 *
 * Required by the KDBX 3.1 inner random stream, where protected fields are
 * XORed against one running Salsa20 keystream in document order.
 */
export class Salsa20 {
  #cipher: KeystreamCipher;

  /**
   * @param key 32-byte key.
   * @param nonce 8-byte nonce.
   * @param counter Initial 64-bit block counter (default 0).
   */
  constructor(key: Uint8Array, nonce: Uint8Array, counter = 0) {
    assertLength(key, KEY_BYTES, 'key');
    assertLength(nonce, SALSA_NONCE_BYTES, 'nonce');
    const k = key.slice();
    const n = nonce.slice();
    this.#cipher = new KeystreamCipher((c) => salsa20Block(k, n, c), counter);
  }

  encrypt(data: Uint8Array): Uint8Array {
    return this.#cipher.process(data);
  }

  decrypt(data: Uint8Array): Uint8Array {
    return this.#cipher.process(data);
  }
}

/**
 * One-shot ChaCha20 (RFC 8439): XOR `data` with the keystream from `counter`.
 * Encryption and decryption are the same operation.
 */
export function chacha20(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter = 0,
): Uint8Array {
  return new ChaCha20(key, nonce, counter).encrypt(data);
}

/**
 * One-shot Salsa20 (Bernstein): XOR `data` with the keystream from `counter`.
 * Encryption and decryption are the same operation.
 */
export function salsa20(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter = 0,
): Uint8Array {
  return new Salsa20(key, nonce, counter).encrypt(data);
}
