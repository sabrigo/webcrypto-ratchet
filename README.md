# webcrypto-ratchet

X3DH key agreement + Double Ratchet session encryption, built entirely on the standard
[WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`crypto.subtle`).
No native bindings, no WASM, no external crypto dependency — it runs anywhere WebCrypto does
(browsers, Node.js, Deno, Cloudflare Workers).

This is a small, from-scratch implementation of the *style* of protocol Signal uses, not the
`libsignal` library itself. See [Security notes](#security-notes) before you rely on it for
anything sensitive.

## What it does

- **X3DH** (`deriveSecretAsInitiator` / `deriveSecretAsRecipient`): a four-way ECDH handshake
  (identity, ephemeral, signed prekey, optional one-time prekey) folded through HKDF-SHA256 into
  a single shared secret, with the signed prekey's signature verified before use.
- **Double Ratchet** (`DoubleRatchetSession`): a fresh AES-256-GCM key for every message, derived
  from a symmetric chain that advances on every send/receive (HMAC-SHA256), plus a DH ratchet
  step whenever the peer's ratchet public key changes — giving you forward secrecy message by
  message, not just session by session.
- **Skipped-message-key handling**: messages that arrive out of order, or late from a chain
  that's since been superseded by a ratchet step, still decrypt correctly via a bounded cache
  (`maxSkip`, default 1000) instead of failing outright. Only a message whose key is genuinely
  gone (already used, or older than the cache retains) is rejected.

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
  exportRawPublic,
  signBytes,
  deriveSecretAsInitiator,
  deriveSecretAsRecipient,
  DoubleRatchetSession,
  bytes,
  text,
} from "webcrypto-ratchet";

// --- one-time setup, per party ---
// A long-term identity keypair (ECDH) and signing keypair (ECDSA), plus a signed prekey
// published somewhere the other party can fetch it from (a server, a QR code, whatever your
// app already uses for key distribution — this library doesn't handle transport or storage).
const identity = await generateDhKeyPair();
const signing = await generateSigningKeyPair();
const signedPreKey = await generateDhKeyPair();
const signedPreKeyPublic = await exportRawPublic(signedPreKey.publicKey);
const signedPreKeySignature = await signBytes(signing.privateKey, signedPreKeyPublic);

// --- the initiator starts a session ---
const ephemeral = await generateDhKeyPair();
const secret = await deriveSecretAsInitiator({
  identityPrivateKey: myIdentity.privateKey,
  ephemeralPrivateKey: ephemeral.privateKey,
  peerIdentityPublicKeyRaw: theirIdentityPublic,
  peerSignedPreKeyPublicRaw: theirSignedPreKeyPublic,
  peerSignedPreKeySignature: theirSignedPreKeySignature,
  peerSigningPublicKeyRaw: theirSigningPublic,
  contextInfo: "your-app-name:some-session-id", // domain separation -- pick a string unique to this session
});

const session = new DoubleRatchetSession();
await session.initAsInitiator(secret, theirSignedPreKeyPublic);

// send whatever handshake metadata your transport needs (identity key, ephemeral key,
// session.localRatchetPublic, which prekey ids you used) to the recipient out of band.

// --- the recipient joins the session ---
const secret2 = await deriveSecretAsRecipient({
  identityPrivateKey: myIdentity.privateKey,
  signedPreKeyPrivateKey: signedPreKey.privateKey,
  peerIdentityPublicKeyRaw: initiatorIdentityPublic,
  peerEphemeralPublicKeyRaw: initiatorEphemeralPublic,
  contextInfo: "your-app-name:some-session-id", // must match exactly
});

const recipientSession = new DoubleRatchetSession();
await recipientSession.initAsRecipient(secret2, {
  initialRatchetKeyPair: signedPreKey,
  initialRatchetPublic: signedPreKeyPublic,
  remoteRatchetPublic: initiatorRatchetPublic, // from the handshake metadata above
});

// --- sending and receiving ---
const frame = await session.encrypt(bytes("hello"));
// frame is JSON-safe: { dh, pn, n, iv, body } -- send it however you like

const plaintext = await recipientSession.decrypt(frame);
console.log(text(plaintext)); // "hello"
```

## Security notes

- **Not an audited implementation.** This is a from-scratch reimplementation of the X3DH/Double
  Ratchet *design*, not the `libsignal` library, and has not had an independent cryptographic
  audit. If you need that guarantee, use `libsignal` (it has WASM/JS bindings) instead.
- **No message header encryption.** The ratchet public key, counters (`n`/`pn`), and IV travel
  as plaintext metadata alongside the ciphertext — only the message body is confidential.
  Signal's production protocol optionally encrypts this metadata ("sealed sender" / header
  encryption); this library doesn't.
- **`maxSkip` bounds memory, not just correctness.** A message claiming a huge counter jump is
  rejected rather than allowed to force unbounded key derivation/caching — tune it down if your
  application doesn't need to tolerate long gaps.
- **You own key storage, transport, and identity verification.** This library derives secrets
  and encrypts/decrypts frames; it has no opinion on how you publish prekeys, authenticate that
  a public key really belongs to who you think it does, or persist session state across restarts.

## Testing

```
npm test
```

Runs the `node:test` suite in `test/`, covering: a full handshake and roundtrip, out-of-order
delivery within one chain, a message that arrives late from a chain already superseded by a DH
ratchet, replay rejection, and the `maxSkip` cap.

## License

MIT — see [LICENSE](./LICENSE).
