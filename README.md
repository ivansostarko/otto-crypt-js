# OTTO Crypt — JS Package


OTTO Crypt JS implements the **OTTO-256-GCM-HKDF-SIV** construction: a pragmatic, misuse-resistant design built on **AES‑256‑GCM**, **HKDF(SHA‑256)**, **Argon2id**, and **X25519**. It supports **chunked streaming encryption** for very large files (photos, docs, audio, video) and an **end‑to‑end (E2E)** mode with ephemeral X25519 key exchange.

> ⚠️ **Security notice**: Although OTTO relies on widely trusted primitives, the overall composition is **custom**. Treat this library as **pre‑audit**. Obtain an **independent cryptographic review** before production.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Programmatic API](#programmatic-api)
- [Algorithm Design](#algorithm-design)
  - [Header](#header)
  - [Chunk Format](#chunk-format)
  - [Key Schedule](#key-schedule)
  - [Nonce Derivation (HKDF‑SIV Style)](#nonce-derivation-hkdf-siv-style)
  - [X25519 E2E Mode](#x25519-e2e-mode)
- [Interoperability with Laravel](#interoperability-with-laravel)
- [Configuration & Defaults](#configuration--defaults)
- [Comparison](#comparison)
- [Security Considerations](#security-considerations)
- [Performance Notes](#performance-notes)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)
- [Responsible Disclosure](#responsible-disclosure)

---

## Features

- **AES‑256‑GCM AEAD** (16‑byte tags).
- **Deterministic per‑chunk nonces** (HKDF‑derived; SIV‑style) to reduce misuse risk.
- **Streaming**: chunked encryption for very large files (default: **1 MiB** per chunk; configurable).
- **E2E session keys** with **X25519** (ephemeral sender key).
- **Password mode** via **Argon2id** (libsodium pwhash).
- **Raw 32‑byte key** mode for advanced setups.
- **Full AD binding**: header is used as Associated Data.
- **CLI** and **Node API** out of the box.
- **Interop** with the Laravel package using the same format and KDFs.

---

## Installation

From a local checkout:
```bash
npm i ./otto-crypt-js
```

(When published to npm):
```bash
npm i otto-crypt-js
```

Node **>=18** is required. Dependency: `libsodium-wrappers` (WASM).

---

## CLI Usage

The package includes a simple CLI at `bin/otto-crypt.js`:

```bash
# Encrypt with password
node ./bin/otto-crypt.js encrypt input.bin output.bin.otto --password="P@ssw0rd!"

# Decrypt with password
node ./bin/otto-crypt.js decrypt output.bin.otto output.dec.bin --password="P@ssw0rd!"

# E2E: encrypt to recipient X25519 public key (base64 or hex)
node ./bin/otto-crypt.js encrypt photo.jpg photo.jpg.otto --recipient="BASE64_OR_HEX_PUBLIC"

# E2E: decrypt with your X25519 secret key (base64 or hex)
node ./bin/otto-crypt.js decrypt photo.jpg.otto photo.jpg --sender-secret="BASE64_OR_HEX_SECRET"

# Raw key (32 bytes in base64/hex/raw)
node ./bin/otto-crypt.js encrypt doc.pdf doc.pdf.otto --raw-key="abcdef..." 
```

> Tip: you can `npm i -g` this local folder to install a global `otto-crypt` command.

---

## Programmatic API

```js
const { OttoCrypt, KeyExchange } = require('otto-crypt-js');

(async () => {
  const otto = new OttoCrypt({ chunkSize: 1024 * 1024 }); // default 1 MiB

  // 1) Strings (single-shot)
  const { cipher, header } = await otto.encryptString(Buffer.from('Hello OTTO'), { password: 'P@ssw0rd!' });
  const plain = await otto.decryptString(cipher, header, { password: 'P@ssw0rd!' });
  console.log(plain.toString()); // Hello OTTO

  // 2) Files (streaming)
  await otto.encryptFile('in.mp4', 'in.mp4.otto', { password: 'P@ssw0rd!' });
  await otto.decryptFile('in.mp4.otto', 'in.dec.mp4', { password: 'P@ssw0rd!' });

  // 3) X25519 E2E
  const { secret, public: pub } = await KeyExchange.generateKeypair();
  await otto.encryptFile('movie.mov', 'movie.mov.otto', { recipient_public: pub.toString('base64') });
  await otto.decryptFile('movie.mov.otto', 'movie.mov', { sender_secret: secret.toString('base64') });
})();
```

**Key exchange helpers:**
```js
const { secret, public: pub } = await KeyExchange.generateKeypair();
const shared = await KeyExchange.deriveSharedSecret(secret, peerPublic);
const sessionKey = KeyExchange.deriveSessionKey(shared, /* salt */ '', /* context */ 'OTTO-X25519-SESSION');
```

---

## Algorithm Design

### Header

Fixed + variable (binary):

```
magic      : "OTTO1" (5 bytes)
algo_id    : 0xA1            # AES-256-GCM + HKDF-SIV nonces
kdf_id     : 0x01=password | 0x02=raw key | 0x03=X25519
flags      : bit0=chunked
reserved   : 0x00
header_len : uint16 BE length of HVAR
HVAR:
  file_salt  (16)
  if kdf=01 (password): pw_salt(16) + opslimit(uint32 BE) + memlimitKiB(uint32 BE)
  if kdf=03 (X25519):   eph_pubkey(32)
```

Associated Data (AD) for all AEAD operations is the entire header (`fixed || HVAR`).

### Chunk Format

For each chunk:
```
chunk_len : uint32 BE of ciphertext length
cipher    : N bytes (same as plaintext size)
tag       : 16 bytes (GCM tag)
```

### Key Schedule

Let `master_key` be obtained via **Argon2id**, **raw key**, or **X25519 ECDH**:

```
enc_key   = HKDF(master_key, len=32, info="OTTO-ENC-KEY",  salt=file_salt)
nonce_key = HKDF(master_key, len=32, info="OTTO-NONCE-KEY", salt=file_salt)
```

### Nonce Derivation (HKDF‑SIV Style)

Deterministic, misuse‑resistant style nonces per chunk:
```
nonce_i = HKDF(nonce_key, len=12, info="OTTO-CHUNK-NONCE" || counter64be, salt="")
```

This helps avoid catastrophic reuse of GCM nonces in streaming scenarios.

### X25519 E2E Mode

- **Sender** generates **ephemeral** X25519 key pair:
  - Shared secret = `scalarmult(eph_sk, recipient_pk)`  
  - `master_key = HKDF(shared, len=32, info="OTTO-E2E-MASTER", salt=file_salt)`
  - Header includes `eph_pubkey`.
- **Recipient** uses their **long‑term secret key** with the **eph_pubkey** to obtain the same shared secret and master key.  
- Forward secrecy at the session level if ephemeral secrets are properly erased.

---

## Interoperability with Laravel

This Node package is **byte‑for‑byte compatible** with the Laravel library `ivansostarko/otto-crypt-php`:

- Same header fields, AEAD parameters, associated data.
- Same KDFs and HKDF contexts/labels.
- Same nonce derivation per chunk.
- Same streaming layout.

**Cross‑test example:** Encrypt a string in Laravel with a password, then decrypt here with the same password and the base64‑encoded header/cipher. The reverse also works.

---

## Configuration & Defaults

Constructor options:
```js
new OttoCrypt({
  chunkSize: 1024 * 1024, // default 1 MiB
  // argon2 tuning (optional — by default uses libsodium MODERATE)
  opslimit: undefined,
  memlimit: undefined
});
```

- **Argon2id** defaults to libsodium’s `OPSLIMIT_MODERATE` / `MEMLIMIT_MODERATE` unless overridden.
- Chunk size can be tuned (1–8 MiB typical).

---

## Comparison

| Scheme | AEAD | Nonce Strategy | Streaming | E2E | Notes |
|---|---|---|---|---|---|
| **OTTO‑256‑GCM‑HKDF‑SIV** | AES‑256‑GCM | **Deterministic HKDF per chunk** | **Yes** | **X25519** | Custom composition; audit recommended |
| AES‑GCM (typical) | AES‑GCM | Random/monotonic (app‑managed) | App‑defined | App‑defined | Easy to misuse via nonce reuse |
| AES‑SIV (RFC 5297) | SIV | Deterministic | App‑defined | App‑defined | Standard MR, slower than GCM |
| ChaCha20‑Poly1305 | ChaCha20/Poly1305 | App‑managed | App‑defined | App‑defined | Fast on non‑AES‑NI CPUs |
| libsodium secretstream | XChaCha20‑Poly1305 | Internal | **Yes** | App‑defined | Excellent, widely used streaming API |

---

## Security Considerations

- **Confidentiality + integrity** via AEAD (GCM) with 16‑byte tags.
- **Misuse resistance**: deterministic nonces mitigate app‑level reuse errors.
- **Password security** depends on the password and Argon2id parameters. Favor **E2E keys** for messengers.
- **Forward secrecy**: E2E uses **ephemeral** sender keys. Erase them after use.
- **Endpoint compromise** (malware) is out of scope.
- **Side‑channels**: uses Node’s `crypto` and libsodium; no additional hardening is provided by this library.
- **Key erasure**: best‑effort zeroing in memory where feasible; the JS runtime might keep copies.
- **Audit**: get a professional cryptographic review before production roll‑out.

---

## Performance Notes

- AES‑GCM uses platform crypto (potentially leveraging AES‑NI).
- HKDF and Argon2id are lightweight relative to large file I/O; Argon2id dominates at session setup time.
- Tune `chunkSize` for throughput vs memory usage.
- For extreme throughput, consider worker threads or a native addon; measure first.

---


## Roadmap

- Cross‑language **test vectors** and fixtures (PHP ↔ Node).
- Optional **AEAD‑SIV** backend (RFC 5297) for standardized MR.
- Multi‑recipient envelope encryption.
- TypeScript typings and ESM build.
- CI: lint, unit tests, and interop tests.

---

## FAQ

**Is this FIPS compliant?**  
Depends on your Node/OpenSSL build. The construction itself is custom and not a NIST standard.

**Can I rotate keys?**  
Yes. Re‑encrypt with a new recipient key or password. The header binds parameters to the ciphertext.

**Why deterministic nonces?**  
To eliminate the risk of accidental nonce reuse in streaming/parallel code, which is catastrophic for GCM.

**Does this replace libsodium secretstream?**  
No. `crypto_secretstream` is fantastic. OTTO focuses on AES‑GCM, interop with Laravel, and built‑in E2E helpers.

---

## Contributing

Contributions are welcome! Please include:
- A clear problem statement and rationale
- Tests (ideally cross‑language when relevant)
- Security notes for crypto‑related changes

Before proposing algorithmic changes, open an issue to discuss implications.

---

## License

MIT © 2025 Ivan Sostarko

---

## Responsible Disclosure

If you believe you have found a vulnerability, **do not open a public issue**.  
Please contact the maintainer privately (see `package.json` author) with details and reproduction steps.  
We’ll coordinate a fix and a responsible disclosure process.
