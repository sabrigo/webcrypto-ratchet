# webcrypto-ratchet

PQXDH key agreement + Triple Ratchet session encryption, built on the standard
[WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`crypto.subtle`)
for everything except the ML-KEM steps, which no browser or runtime exposes natively yet — those
come from [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum), an audited,
dependency-light implementation. Runs anywhere both WebCrypto and plain JS run (browsers, Node.js,
Deno, Cloudflare Workers).

This is a small, from-scratch implementation of the *style* of protocol Signal uses, not the
`libsignal` library itself. See [Security notes](#security-notes) before you rely on it for
anything sensitive.

## What it does

- **PQXDH** (`deriveSecretAsInitiator` / `deriveSecretAsRecipient`): a four-way X25519 handshake
  (identity, ephemeral, signed prekey, optional one-time prekey) plus an ML-KEM-768 encapsulation
  against a signed PQ prekey, folded together through HKDF-SHA256 into a single shared secret —
  following the design of Signal's production PQXDH (the KDF encoding details differ; see
  [Security notes](#security-notes)). Both the signed prekey's and the PQ prekey's signatures
  are verified before use.
- **Triple Ratchet** (`DoubleRatchetSession`): a fresh AES-256-GCM key for every message, derived
  from a symmetric chain that advances on every send/receive (HMAC-SHA256), plus a ratchet step
  whenever the peer's ratchet keys change — giving you forward secrecy message by message, not
  just session by session. That ratchet step runs two independent public-key ratchets side by
  side and mixes both outputs together, matching Signal's own production Triple Ratchet (Double
  Ratchet + [SPQR](https://signal.org/blog/spqr/)): a classical X25519 DH ratchet, plus an
  ML-KEM-768 ratchet that advances in lockstep with it. An attacker has to break *both* X25519 and
  ML-KEM to recover a step's chain key — including a future quantum computer that breaks one but
  not the other.
- **Skipped-message-key handling**: messages that arrive out of order, or late from a chain
  that's since been superseded by one or more ratchet steps, still decrypt correctly via a
  bounded cache (`maxSkip`, default 1000) instead of failing outright. Only a message whose key
  is genuinely gone (already used, or older than the cache retains) is rejected.
- **Encrypted headers**: the ratchet public keys, KEM ciphertext, and message counters travel
  encrypted, under a key that itself rotates on every ratchet step (Signal's "Double Ratchet with
  header encryption" extension) — an observer of the wire frames sees only opaque ciphertext, not
  message cadence or ratchet timing, on top of message content already being confidential.
- **Atomic decryption**: session state (chain keys, counters, the skip cache, ratchet keypairs)
  only commits after the message body's AES-GCM tag verifies — anything that throws mid-decrypt
  rolls every mutation back, per the Double Ratchet spec's "state is only updated if decryption
  succeeds" requirement. A valid header only proves knowledge of a header key, not body
  authenticity, so without this an on-path attacker replaying a real frame with a bit-flipped
  body could burn the genuine message's key (making it permanently undecryptable), evict a
  skipped message's cached key, or force a spurious ratchet step — all with zero key material.

## How it compares

The short version: **if a maintained, audited implementation fits your runtime and licensing
constraints, use it instead of this.** This library exists for the gap where none does — pure-JS
runtimes (browsers, Cloudflare Workers, Deno) that need PQXDH-style handshakes and a
post-quantum ratchet today, under a permissive license, without shipping native binaries or WASM.

| | **webcrypto-ratchet** | [`@signalapp/libsignal-client`](https://github.com/signalapp/libsignal) | [`vodozemac`](https://github.com/matrix-org/vodozemac) (Matrix) | [`libsignal-protocol-javascript`](https://github.com/signalapp/libsignal-protocol-javascript) |
|---|---|---|---|---|
| **Audited** | ❌ No | ✅ Signal's production core (Rust) | ✅ Least Authority audit | ❌ Deprecated, unmaintained |
| **Runs in browsers / edge** | ✅ Anywhere WebCrypto + JS run | ❌ Native binaries for Node on Win/macOS/Linux only; no official browser build | ⚠️ Via WASM bindings | ✅ (but abandoned) |
| **PQ handshake** | ✅ PQXDH-style (ML-KEM-768) | ✅ PQXDH | ❌ Classical 3DH (PQ listed as future work) | ❌ X3DH only |
| **PQ ratchet** | ✅ ML-KEM mixed into every step | ✅ SPQR | ❌ | ❌ |
| **Encrypted headers** | ✅ | ❌ (not used by Signal's wire protocol) | ❌ | ❌ |
| **Wire-compatible with Signal / Matrix** | ❌ (non-goal) | ✅ Signal | ✅ Matrix/Olm | ✅ Signal (historical) |
| **Group messaging** | ❌ Pairwise only | ✅ (sender keys, zkgroup) | ✅ (Megolm) | ❌ |
| **License** | MIT | AGPLv3 | Apache-2.0 | GPLv3 |
| **Dependencies** | 1 (`@noble/post-quantum`, audited) | Native module + Rust toolchain to build | Rust crate / WASM artifact | None (vendored C) |
| **Key storage / prekey server** | Bring your own | Bring your own (store interfaces) | Pickling built in | Store interfaces |

Where each is the right call:

- **`@signalapp/libsignal-client`** — the default answer for anything high-stakes. It's the
  production core of Signal itself, in Rust with TypeScript bindings, with PQXDH and the SPQR
  post-quantum ratchet. Two constraints push people elsewhere: it ships as a **native Node
  module** (Signal publishes builds for Windows/macOS/Linux — Signal Desktop is Electron, so
  Signal itself never needs a browser build), and it's **AGPLv3**, which is a hard blocker for
  many closed-source commercial products. The old pure-JS browser library is officially
  deprecated in its favor.
- **`vodozemac`** — the audited Rust implementation of Matrix's Olm/Megolm, usable from the web
  via WASM bindings, Apache-2.0. Strong choice if you want Matrix interop or group messaging.
  No post-quantum handshake or ratchet at the time of writing (its docs describe layering
  external/PQ KEMs on top as an advanced use case), and its recent public
  cryptographic scrutiny has been contentious — read both the reports and the maintainers'
  responses and judge for yourself.
- **[OpenMLS / MLS (RFC 9420)](https://github.com/openmls/openmls)** — not in the table because
  it solves a different problem: scalable *group* key agreement. If your product is
  many-to-many rooms rather than pairwise sessions, MLS is the standards-track answer and a
  pairwise ratchet (this library included) is the wrong shape.
- **webcrypto-ratchet** — pairwise sessions in pure JS where you control both endpoints and the
  wire format, want PQ coverage at both the handshake *and* every ratchet step, need encrypted
  headers, and want MIT licensing with a single audited dependency. You accept the tradeoffs in
  [Security notes](#security-notes): no independent audit, no Signal interop, no groups, and
  ~3 KB/message of ML-KEM overhead.

Interoperability with any of the above is explicitly a non-goal — this library's wire format
(JSON frames, encrypted headers carrying whole KEM payloads) and KDF encoding are its own.

## Install

Not yet published to npm. Until then, point at it directly:

```json
{
  "dependencies": {
    "webcrypto-ratchet": "file:../path/to/webcrypto-ratchet"
  }
}
```

## Usage

```js
import {
  generateDhKeyPair,
  generateSigningKeyPair,
  generatePqPreKeyPair,
  exportRawPublic,
  signBytes,
  deriveSecretAsInitiator,
  deriveSecretAsRecipient,
  DoubleRatchetSession,
  bytes,
  text,
} from "webcrypto-ratchet";

// --- one-time setup, per party ---
// A long-term identity keypair (X25519) and signing keypair (Ed25519), plus a signed prekey and
// a signed PQ (ML-KEM-768) prekey, published somewhere the other party can fetch them from (a
// server, a QR code, whatever your app already uses for key distribution — this library doesn't
// handle transport or storage).
const identity = await generateDhKeyPair();
const signing = await generateSigningKeyPair();
const signedPreKey = await generateDhKeyPair();
const signedPreKeyPublic = await exportRawPublic(signedPreKey.publicKey);
const signedPreKeySignature = await signBytes(signing.privateKey, signedPreKeyPublic);
const pqPreKey = generatePqPreKeyPair();
const pqPreKeySignature = await signBytes(signing.privateKey, pqPreKey.publicKey);

// --- the initiator starts a session ---
const ephemeral = await generateDhKeyPair();
const { secret, pqCipherText } = await deriveSecretAsInitiator({
  identityPrivateKey: myIdentity.privateKey,
  ephemeralPrivateKey: ephemeral.privateKey,
  peerIdentityPublicKeyRaw: theirIdentityPublic,
  peerSignedPreKeyPublicRaw: theirSignedPreKeyPublic,
  peerSignedPreKeySignature: theirSignedPreKeySignature,
  peerSigningPublicKeyRaw: theirSigningPublic,
  peerPqPreKeyPublic: theirPqPreKeyPublic,
  peerPqPreKeySignature: theirPqPreKeySignature,
  contextInfo: "your-app-name:some-session-id", // domain separation -- pick a string unique to this session
});

const session = new DoubleRatchetSession();
await session.initAsInitiator(secret, theirSignedPreKeyPublic, theirPqPreKeyPublic);

// send whatever handshake metadata your transport needs (identity key, ephemeral key,
// pqCipherText, session.localRatchetPublic, session.localPqRatchet.publicKey, session.pqCtToSend,
// which prekey ids you used) to the recipient out of band.

// --- the recipient joins the session ---
const secret2 = await deriveSecretAsRecipient({
  identityPrivateKey: myIdentity.privateKey,
  signedPreKeyPrivateKey: signedPreKey.privateKey,
  peerIdentityPublicKeyRaw: initiatorIdentityPublic,
  peerEphemeralPublicKeyRaw: initiatorEphemeralPublic,
  pqPreKeySecretKey: pqPreKey.secretKey,
  pqCipherText: initiatorPqCipherText, // from the handshake metadata above
  contextInfo: "your-app-name:some-session-id", // must match exactly
});

const recipientSession = new DoubleRatchetSession();
await recipientSession.initAsRecipient(secret2, {
  initialRatchetKeyPair: signedPreKey,
  initialRatchetPublic: signedPreKeyPublic,
  initialPqRatchetKeyPair: pqPreKey,
  remoteRatchetPublic: initiatorRatchetPublic, // from the handshake metadata above
  remotePqRatchetPublic: initiatorPqRatchetPublic, // session.localPqRatchet.publicKey, above
  remotePqCipherText: initiatorPqCtToSend, // session.pqCtToSend, above -- NOT the PQXDH pqCipherText
});

// --- sending and receiving ---
const frame = await session.encrypt(bytes("hello"));
// frame is a single Uint8Array: headerIv(12) || headerCiphertext(2329) || bodyIv(12) || body.
// Send it as a binary WebSocket/fetch payload, or base64 the whole thing once for JSON
// transports (uint8ToBase64 / base64ToUint8 are exported). The ratchet keys and counters ride
// inside the encrypted header -- nothing on the wire is plaintext, and every frame is the same
// size for the same plaintext length, ratchet step or not.

const plaintext = await recipientSession.decrypt(frame);
console.log(text(plaintext)); // "hello"
```

## Security notes

- **Not an audited implementation.** This is a from-scratch reimplementation of the PQXDH/Triple
  Ratchet *design*, not the `libsignal` library, and has not had an independent cryptographic
  audit — though the one non-WebCrypto primitive it uses, ML-KEM-768, comes from `@noble/post-quantum`,
  which is independently audited. If you need a fully audited stack, use `libsignal` (it has
  WASM/JS bindings) instead.
- **Header encryption protects metadata, not content.** Message content was already fully
  confidential via AES-256-GCM before this was added — encrypting `{dh, pqEk, pqCt, pn, n}`
  additionally hides message cadence and ratchet timing from anyone who sees the wire frames. It
  doesn't change what was already protected, only what else now is.
- **`maxSkip` bounds memory, not just correctness.** A message claiming a huge counter jump is
  rejected rather than allowed to force unbounded key derivation/caching — tune it down if your
  application doesn't need to tolerate long gaps.
- **You own key storage, transport, and identity verification.** This library derives secrets
  and encrypts/decrypts frames; it has no opinion on how you publish prekeys, authenticate that
  a public key really belongs to who you think it does, or persist session state across restarts.
- **PQ resistance is continuous, not just at the handshake.** Every ratchet step (every time
  `_advance` runs, not only the initial PQXDH) mixes in a fresh ML-KEM-768 shared secret alongside
  the X25519 DH output, matching Signal's production Triple Ratchet. Breaking X25519 alone (now,
  or with a future quantum computer) is not enough to recover any step's chain key; ML-KEM would
  also have to fall.
- **No SPQR-style bandwidth chunking — every frame carries the KEM material.** Signal's SPQR
  spreads its ML-KEM payload across multiple messages via erasure coding, purely to fit legacy
  per-message size budgets. This library sends the ML-KEM public key (1,184 bytes) and ciphertext
  (1,088 bytes) whole, inside the encrypted header of **every message** — not just
  ratchet-carrying ones. With the fixed-offset binary framing that's 2,369 bytes of overhead per
  message on binary transports (~3.2&nbsp;KB if you base64 the frame once for JSON). The upside
  of the constant size is that ratchet-carrying frames are indistinguishable from ordinary ones
  even by length; the downside is per-message bandwidth. A tradeoff, not a vulnerability.
- **The wire format is fixed-offset binary, versioned inside the encrypted header.** Every header
  field is a fixed length (X25519 and ML-KEM-768 sizes are constants of the algorithms), so
  frames parse by offset with no length prefixes, no JSON, and no nested base64. A version byte
  travels *inside* the header ciphertext — authenticated, so downgrade games with the format
  version are not possible from the wire.
- **Not byte-for-byte Signal's KDF.** The PQXDH secret here is
  `HKDF(DH1‖DH2‖DH3‖DH4‖SS, salt=SHA-256("pqxdh-v1:"+contextInfo))`; Signal's spec instead
  prepends a 32-byte `0xFF` pad and uses a zero salt, and signs prekeys with XEdDSA from a single
  identity key where this library uses a separate Ed25519 signing key. Same structure and DH/KEM
  inputs, different encoding — interoperability with libsignal is a non-goal.
- **Bind identities via `contextInfo` — the library doesn't do it for you.** X3DH's spec binds
  both parties' identity keys into the first message's associated data; here the identities enter
  the shared secret through DH1/DH2 but are not folded into the AEAD. Put both identity public
  keys (or a hash of them) into `contextInfo` to get the equivalent binding and close
  unknown-key-share edge cases.
- **Handshakes are replayable without one-time prekeys.** If the initiator uses no one-time
  prekey (and there are no one-time *PQ* prekeys at all — only the signed PQ prekey), an attacker
  can replay a recorded handshake plus first messages to the recipient, who will derive the same
  secret and accept the duplicates as a fresh session. This is X3DH's documented limitation, not
  something this library adds — supply one-time prekeys and/or detect duplicate sessions at the
  application layer.
- **Private keys are generated extractable.** X25519/Ed25519 keypairs come from
  `generateKey(..., extractable=true, ...)` so callers can persist them — which also means any
  code that can reach the `CryptoKey` objects (e.g. via XSS in a browser) can export them. If you
  don't need export, re-import your long-term keys as non-extractable in your own storage layer.
  Chain and root keys live as plain `Uint8Array`s with no zeroization, as is effectively
  unavoidable in JavaScript.

## Testing

```
npm test
```

Runs the `node:test` suite in `test/`, covering: signed-prekey and PQ-prekey signature rejection,
a full PQXDH handshake and roundtrip, confirming the wire frame carries no plaintext routing
metadata, header-ciphertext tamper detection, out-of-order delivery within one chain, a message
that arrives late from a chain superseded by a ratchet step (including one skipped two ratchet
generations ago -- exercising several rounds of the X25519+ML-KEM ratchet steps back to back),
replay rejection, the `maxSkip` cap, and an HKDF cross-check against node:crypto's independent
implementation using RFC 5869's test vector. Three regression tests pin the atomic-decryption
guarantee: a tampered body must not burn the in-order message key (the genuine frame still
decrypts afterward), must not advance or desync the ratchet when it rides a ratchet-carrying
frame (the session keeps working in both directions), and must not evict a skipped message's
cached key. The wire-format tests pin that a frame is a single `Uint8Array` containing no
verbatim key-material bytes, and that frames are constant-size for equal plaintexts whether or
not they carry a ratchet step.

## License

MIT — see [LICENSE](./LICENSE).