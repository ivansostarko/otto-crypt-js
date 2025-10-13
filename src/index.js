'use strict';

const crypto = require('crypto');
const fs = require('fs');
const sodium = require('libsodium-wrappers');

const MAGIC = Buffer.from('OTTO1', 'ascii'); // 5 bytes
const ALGO_ID = 0xA1;
const KDF_PASSWORD = 0x01;
const KDF_RAWKEY   = 0x02;
const KDF_X25519   = 0x03;
const FLAG_CHUNKED = 0x01;

const DEFAULT_CHUNK = 1024 * 1024; // 1MiB

class HKDF {
  static derive(ikm, length, info = Buffer.alloc(0), salt = Buffer.alloc(0), hash = 'sha256') {
    if (!Buffer.isBuffer(ikm)) ikm = Buffer.from(ikm);
    if (!Buffer.isBuffer(info)) info = Buffer.from(info);
    if (!Buffer.isBuffer(salt)) salt = Buffer.from(salt);
    return crypto.hkdfSync(hash, ikm, salt, info, length);
  }
}

function be16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n >>> 0, 0);
  return b;
}
function be32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}
function readU32BE(buf, off) { return buf.readUInt32BE(off); }

function decodeKey(txt) {
  if (Buffer.isBuffer(txt)) return txt;
  if (typeof txt !== 'string') return Buffer.from([]);
  const s = txt.trim();

  // Heuristic: hex?
  if (/^[0-9a-fA-F]+$/.test(s) && (s.length % 2 === 0)) {
    try { return Buffer.from(s, 'hex'); } catch {}
  }
  // Heuristic: base64?
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    try {
      const b = Buffer.from(s, 'base64');
      if (b.length > 0) return b;
    } catch {}
  }
  // raw utf-8 fallback
  return Buffer.from(s, 'utf8');
}

function chunkNonce(nonceKey, counter) {
  // counter is a JS BigInt or Number
  let c = BigInt(counter);
  const hi = Number((c >> 32n) & 0xffffffffn);
  const lo = Number(c & 0xffffffffn);
  const info = Buffer.concat([Buffer.from('OTTO-CHUNK-NONCE', 'ascii'), be32(hi), be32(lo)]);
  return HKDF.derive(nonceKey, 12, info, Buffer.alloc(0), 'sha256');
}

async function ensureSodium() {
  if (!sodium.ready) { await sodium.ready; } else { await sodium.ready; }
  return sodium;
}

class KeyExchange {
  static async generateKeypair() {
    const s = await ensureSodium();
    const sk = s.randombytes_buf(s.crypto_scalarmult_SCALARBYTES);
    const pk = s.crypto_scalarmult_base(sk);
    return { secret: Buffer.from(sk), public: Buffer.from(pk) };
  }
  static async deriveSharedSecret(mySecret, theirPublic) {
    const s = await ensureSodium();
    const sk = Buffer.isBuffer(mySecret) ? mySecret : decodeKey(mySecret);
    const pk = Buffer.isBuffer(theirPublic) ? theirPublic : decodeKey(theirPublic);
    if (sk.length !== s.crypto_scalarmult_SCALARBYTES) throw new Error('sender_secret invalid length');
    if (pk.length !== s.crypto_scalarmult_BYTES) throw new Error('recipient_public invalid length');
    const shared = s.crypto_scalarmult(sk, pk);
    return Buffer.from(shared);
  }
  static deriveSessionKey(sharedSecret, salt = Buffer.alloc(0), context = 'OTTO-X25519-SESSION') {
    const info = Buffer.from(context, 'ascii');
    return HKDF.derive(sharedSecret, 32, info, Buffer.isBuffer(salt)? salt : Buffer.from(salt), 'sha256');
  }
}

class OttoCrypt {
  constructor(opts = {}) {
    this.chunkSize = opts.chunkSize || DEFAULT_CHUNK;
    this.argonOpslimit = opts.opslimit || null; // if null, use sodium's MODERATE
    this.argonMemlimit = opts.memlimit || null;
  }

  async encryptString(plaintextBuf, options = {}) {
    await ensureSodium();
    const ctx = await this.initContext(options, /*chunked*/ false);
    const { encKey, nonceKey, header } = ctx;
    const ad = header;

    const nonce = chunkNonce(nonceKey, 0);
    const { cipher, tag } = this.aesGcmEncrypt(plaintextBuf, encKey, nonce, ad);
    return { cipher: Buffer.concat([cipher, tag]), header };
  }

  async decryptString(cipherAndTag, headerBuf, options = {}) {
    await ensureSodium();
    const ctx = await this.initContextForDecryption(headerBuf, options);
    const { encKey, nonceKey, ad } = ctx;

    if (cipherAndTag.length < 16) throw new Error('Ciphertext too short');
    const cipher = cipherAndTag.subarray(0, cipherAndTag.length - 16);
    const tag = cipherAndTag.subarray(cipherAndTag.length - 16);

    const nonce = chunkNonce(nonceKey, 0);
    return this.aesGcmDecrypt(cipher, tag, encKey, nonce, ad);
  }

  async encryptFile(inPath, outPath, options = {}) {
    await ensureSodium();
    const ctx = await this.initContext(options, /*chunked*/ true);
    const { encKey, nonceKey, header } = ctx;
    const ad = header;

    const inFd = fs.openSync(inPath, 'r');
    const outFd = fs.openSync(outPath, 'w');

    try {
      // write header
      fs.writeFileSync(outFd, header);

      let counter = 0n;
      const buf = Buffer.alloc(this.chunkSize);
      let pos = 0;
      while (true) {
        const read = fs.readSync(inFd, buf, 0, buf.length, pos);
        if (read === 0) break;
        const chunk = buf.subarray(0, read);
        const nonce = chunkNonce(nonceKey, counter);
        const { cipher, tag } = this.aesGcmEncrypt(chunk, encKey, nonce, ad);
        // length, cipher, tag
        const len = be32(cipher.length);
        fs.writeFileSync(outFd, len);
        fs.writeFileSync(outFd, cipher);
        fs.writeFileSync(outFd, tag);
        counter++;
        pos += read;
      }
    } finally {
      fs.closeSync(inFd);
      fs.closeSync(outFd);
      // best-effort zero
      encKey.fill(0); nonceKey.fill(0);
      if (ctx.masterKey) ctx.masterKey.fill(0);
    }
  }

  async decryptFile(inPath, outPath, options = {}) {
    await ensureSodium();
    const inFd = fs.openSync(inPath, 'r');
    let pos = 0;

    try {
      // read fixed header prefix (11 bytes)
      const fixed = Buffer.alloc(11);
      const r0 = fs.readSync(inFd, fixed, 0, 11, pos);
      if (r0 !== 11) throw new Error('Bad header');
      pos += 11;

      if (!fixed.subarray(0,5).equals(MAGIC)) throw new Error('Bad magic');
      const algo = fixed[5];
      if (algo !== ALGO_ID) throw new Error('Unsupported algo');
      const hlen = fixed.readUInt16BE(9); // bytes 9-10
      const varPart = Buffer.alloc(hlen);
      const r1 = fs.readSync(inFd, varPart, 0, hlen, pos);
      if (r1 !== hlen) throw new Error('Truncated header');
      pos += hlen;
      const header = Buffer.concat([fixed, varPart]);

      const ctx = await this.initContextForDecryption(header, options);
      const { encKey, nonceKey, ad } = ctx;

      const outFd = fs.openSync(outPath, 'w');
      try {
        let counter = 0n;
        const lenBuf = Buffer.alloc(4);
        while (true) {
          const rlen = fs.readSync(inFd, lenBuf, 0, 4, pos);
          if (rlen === 0) break; // EOF
          if (rlen < 4) throw new Error('Truncated chunk length');
          pos += 4;
          const clen = readU32BE(lenBuf, 0);
          if (clen <= 0) break;
          const cipher = Buffer.alloc(clen);
          const rc = fs.readSync(inFd, cipher, 0, clen, pos);
          if (rc !== clen) throw new Error('Truncated cipher');
          pos += clen;
          const tag = Buffer.alloc(16);
          const rt = fs.readSync(inFd, tag, 0, 16, pos);
          if (rt !== 16) throw new Error('Missing tag');
          pos += 16;

          const nonce = chunkNonce(nonceKey, counter);
          const plain = this.aesGcmDecrypt(cipher, tag, encKey, nonce, ad);
          fs.writeFileSync(outFd, plain);
          counter++;
        }
      } finally {
        fs.closeSync(outFd);
        encKey.fill(0); nonceKey.fill(0);
        if (ctx.masterKey) ctx.masterKey.fill(0);
      }
    } finally {
      fs.closeSync(inFd);
    }
  }

  // ===== helpers =====
  aesGcmEncrypt(plain, key, nonce, aad) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const c1 = cipher.update(plain);
    const c2 = cipher.final();
    const tag = cipher.getAuthTag();
    return { cipher: Buffer.concat([c1, c2]), tag };
  }
  aesGcmDecrypt(cipherText, tag, key, nonce, aad) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const p1 = decipher.update(cipherText);
    const p2 = decipher.final();
    return Buffer.concat([p1, p2]);
  }

  async initContext(options, chunked) {
    const s = await ensureSodium();
    const fileSalt = crypto.randomBytes(16);
    const algoId = Buffer.from([ALGO_ID]);
    const flags = Buffer.from([chunked ? FLAG_CHUNKED : 0]);
    const reserved = Buffer.from([0]);

    let kdfId;
    let headerExtra = Buffer.alloc(0);
    let masterKey;

    // Normalize option names (accept both snake_case and camelCase)
    const password = options.password;
    const raw_key = options.raw_key || options.rawKey;
    const recipient_public = options.recipient_public || options.recipientPublic;

    if (typeof password === 'string') {
      kdfId = Buffer.from([KDF_PASSWORD]);
      const pwSalt = crypto.randomBytes(16);
      const opslimit = this.argonOpslimit ?? s.crypto_pwhash_OPSLIMIT_MODERATE;
      const memlimit = this.argonMemlimit ?? s.crypto_pwhash_MEMLIMIT_MODERATE;
      const key = s.crypto_pwhash(32, password, pwSalt, opslimit, memlimit, s.crypto_pwhash_ALG_ARGON2ID13);
      masterKey = Buffer.from(key);
      headerExtra = Buffer.concat([
        pwSalt,
        be32(opslimit >>> 0),
        be32((memlimit / 1024) >>> 0) // store KiB
      ]);
    } else if (raw_key) {
      kdfId = Buffer.from([KDF_RAWKEY]);
      const raw = Buffer.isBuffer(raw_key) ? raw_key : decodeKey(raw_key);
      if (raw.length !== 32) throw new Error('raw_key must be 32 bytes');
      masterKey = Buffer.from(raw);
    } else if (recipient_public) {
      kdfId = Buffer.from([KDF_X25519]);
      const rcpt = Buffer.isBuffer(recipient_public) ? recipient_public : decodeKey(recipient_public);
      if (rcpt.length !== s.crypto_scalarmult_BYTES) throw new Error('recipient_public invalid length');
      const ephSk = s.randombytes_buf(s.crypto_scalarmult_SCALARBYTES);
      const ephPk = s.crypto_scalarmult_base(ephSk);
      const shared = s.crypto_scalarmult(ephSk, rcpt);
      masterKey = HKDF.derive(Buffer.from(shared), 32, Buffer.from('OTTO-E2E-MASTER','ascii'), fileSalt, 'sha256');
      // header carries ephemeral public
      headerExtra = Buffer.from(ephPk);
      // zero ephemeral
      ephSk.fill(0); shared.fill(0);
    } else {
      throw new Error('Provide one of: password, raw_key, recipient_public');
    }

    const encKey = HKDF.derive(masterKey, 32, Buffer.from('OTTO-ENC-KEY','ascii'), fileSalt, 'sha256');
    const nonceKey = HKDF.derive(masterKey, 32, Buffer.from('OTTO-NONCE-KEY','ascii'), fileSalt, 'sha256');

    const varPart = Buffer.concat([fileSalt, headerExtra]);
    const headerLen = be16(varPart.length);
    const kdfIdBuf = kdfId;
    const header = Buffer.concat([
      MAGIC,
      algoId,
      kdfIdBuf,
      flags,
      reserved,
      headerLen,
      varPart
    ]);

    return {
      header,
      ad: header,
      encKey,
      nonceKey,
      masterKey
    };
  }

  async initContextForDecryption(headerBuf, options) {
    const s = await ensureSodium();
    if (!Buffer.isBuffer(headerBuf)) headerBuf = Buffer.from(headerBuf);

    if (headerBuf.length < 11) throw new Error('Header too short');
    if (!headerBuf.subarray(0,5).equals(MAGIC)) throw new Error('Bad magic');
    const algo = headerBuf[5];
    if (algo !== ALGO_ID) throw new Error('Unsupported algo');

    const kdf = headerBuf[6];
    const hlen = headerBuf.readUInt16BE(9);
    const varStart = 11;
    const varEnd = varStart + hlen;
    if (headerBuf.length < varEnd) throw new Error('Truncated header');
    const varPart = headerBuf.subarray(varStart, varEnd);

    let off = 0;
    const fileSalt = varPart.subarray(off, off+16); off += 16;
    let masterKey;

    if (kdf === KDF_PASSWORD) {
      const pwSalt = varPart.subarray(off, off+16); off += 16;
      const opslimit = varPart.readUInt32BE(off); off += 4;
      const memKiB   = varPart.readUInt32BE(off); off += 4;
      const memlimit = memKiB * 1024;

      const pw = options.password;
      if (typeof pw !== 'string') throw new Error('Password required');
      const key = s.crypto_pwhash(32, pw, pwSalt, opslimit, memlimit, s.crypto_pwhash_ALG_ARGON2ID13);
      masterKey = Buffer.from(key);
    } else if (kdf === KDF_RAWKEY) {
      const raw = options.raw_key || options.rawKey;
      const rk = Buffer.isBuffer(raw) ? raw : decodeKey(raw || '');
      if (rk.length !== 32) throw new Error('raw_key (32 bytes) required');
      masterKey = Buffer.from(rk);
    } else if (kdf === KDF_X25519) {
      const ephPk = varPart.subarray(off, off + s.crypto_scalarmult_BYTES); off += s.crypto_scalarmult_BYTES;
      const sender_secret = options.sender_secret || options.senderSecret;
      const sk = Buffer.isBuffer(sender_secret) ? sender_secret : decodeKey(sender_secret || '');
      if (sk.length !== s.crypto_scalarmult_SCALARBYTES) throw new Error('sender_secret invalid length');
      const shared = s.crypto_scalarmult(sk, ephPk);
      masterKey = HKDF.derive(Buffer.from(shared), 32, Buffer.from('OTTO-E2E-MASTER','ascii'), fileSalt, 'sha256');
    } else {
      throw new Error('Unknown KDF');
    }

    const encKey = HKDF.derive(masterKey, 32, Buffer.from('OTTO-ENC-KEY','ascii'), fileSalt, 'sha256');
    const nonceKey = HKDF.derive(masterKey, 32, Buffer.from('OTTO-NONCE-KEY','ascii'), fileSalt, 'sha256');

    return {
      ad: headerBuf.subarray(0, 11 + hlen),
      encKey,
      nonceKey,
      masterKey
    };
  }
}

module.exports = { OttoCrypt, KeyExchange };
