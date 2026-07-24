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
  matching Signal's own production PQXDH. Both the signed prekey's and the PQ prekey's signatures
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
// frame is JSON-safe: { headerIv, header, iv, body } -- send it however you like.
// The ratchet key and counters are inside the encrypted `header`, not visible on the wire.

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
- **No SPQR-style bandwidth chunking.** Signal's SPQR spreads its ~1KB-per-step ML-KEM payload
  across multiple messages via erasure coding, purely to fit legacy per-message size budgets. This
  library sends the ML-KEM public key and ciphertext whole, inside the already-encrypted header —
  simpler, but it does mean each ratchet-carrying frame is a few KB larger than a pure-X25519
  Double Ratchet's. That's a bandwidth tradeoff, not a security one.

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
implementation using RFC 5869's test vector.

## License

MIT — see [LICENSE](./LICENSE).
