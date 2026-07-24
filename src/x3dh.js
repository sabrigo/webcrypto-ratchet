// PQXDH: X3DH generalized from the Signal design (four X25519 exchanges -- identity/signed-
// prekey/ephemeral/one-time-prekey combinations) plus an ML-KEM-768 encapsulation against the
// peer's signed PQ prekey, all folded through HKDF into a single 32-byte shared secret. This
// matches Signal's own production PQXDH: the classical DH outputs alone are only as strong as
// X25519 against a future quantum adversary, so the KEM secret is mixed in too -- breaking
// either the classical or the post-quantum half alone isn't enough to recover the root secret.
// Both the signed prekey's and the PQ prekey's signatures are checked before use. Callers pass
// already-decoded CryptoKey/Uint8Array material -- this module has no opinion on wire format
// (base64, JSON shape, etc.), that's the caller's job.
import { dh, hkdf, sha256, bytes, concatBytes, verifyBytes } from "./primitives.js";
import { generatePqKeyPair, pqEncapsulate, pqDecapsulate } from "./pq.js";

/** Generates a fresh ML-KEM-768 keypair for use as a signed PQ prekey. Sign publicKey with your
 * Ed25519 identity key (same as a signed prekey) before publishing it. */
export const generatePqPreKeyPair = generatePqKeyPair;

const IDENTITY_KEY_LENGTH = 32; // X25519 raw public key

// The X3DH spec binds AD = Encode(IK_initiator) || Encode(IK_recipient) into the protocol so
// that a secret can only ever be interpreted as belonging to one ordered pair of identities --
// closing unknown-key-share attacks where a MITM convinces one party they're talking to someone
// else without breaking any DH. The identity keys already enter the DH outputs (dh1/dh2), but
// folding them into the KDF *by role* is what pins WHO is initiator and WHO is recipient. Both
// fields are fixed-length, so concatenation is unambiguous without length prefixes.
async function x3dhRootSecret(dhOutputs, pqSharedSecret, contextInfo, initiatorIdentityPublic, recipientIdentityPublic) {
  if (initiatorIdentityPublic.length !== IDENTITY_KEY_LENGTH) throw new Error("Invalid initiator identity key length");
  if (recipientIdentityPublic.length !== IDENTITY_KEY_LENGTH) throw new Error("Invalid recipient identity key length");
  const salt = await sha256(bytes(`pqxdh-v2:${contextInfo}`));
  const info = concatBytes(bytes("webcrypto-ratchet-pqxdh-root-v2"), initiatorIdentityPublic, recipientIdentityPublic);
  return hkdf(concatBytes(...dhOutputs, pqSharedSecret), salt, info, 32);
}

/**
 * @param {object} params
 * @param {CryptoKey} params.identityPrivateKey - our long-term X25519 identity private key
 * @param {Uint8Array} params.identityPublicKeyRaw - our long-term X25519 identity public key (raw),
 *   bound into the KDF alongside the peer's so the secret pins both identities in their roles
 * @param {CryptoKey} params.ephemeralPrivateKey - a fresh X25519 keypair's private key, generated for this handshake
 * @param {Uint8Array} params.peerIdentityPublicKeyRaw - peer's long-term X25519 identity public key
 * @param {Uint8Array} params.peerSignedPreKeyPublicRaw - peer's published signed prekey (X25519 public)
 * @param {Uint8Array} params.peerSignedPreKeySignature - signature over peerSignedPreKeyPublicRaw
 * @param {Uint8Array} params.peerSigningPublicKeyRaw - peer's long-term Ed25519 signing public key
 * @param {Uint8Array} params.peerPqPreKeyPublic - peer's published ML-KEM-768 PQ prekey (from generatePqPreKeyPair)
 * @param {Uint8Array} params.peerPqPreKeySignature - signature over peerPqPreKeyPublic
 * @param {Uint8Array|null} [params.peerOneTimePreKeyPublicRaw] - peer's one-time prekey, if one was available
 * @param {string} params.contextInfo - caller-supplied domain-separation string (e.g. a session/room id)
 * @returns {Promise<{secret: Uint8Array, pqCipherText: Uint8Array}>} the 32-byte shared secret to
 *   seed the Double Ratchet, plus the ML-KEM ciphertext the recipient needs to decapsulate --
 *   send pqCipherText alongside the usual handshake metadata (identity key, ephemeral key, etc.)
 */
export async function deriveSecretAsInitiator({
  identityPrivateKey,
  identityPublicKeyRaw,
  ephemeralPrivateKey,
  peerIdentityPublicKeyRaw,
  peerSignedPreKeyPublicRaw,
  peerSignedPreKeySignature,
  peerSigningPublicKeyRaw,
  peerPqPreKeyPublic,
  peerPqPreKeySignature,
  peerOneTimePreKeyPublicRaw = null,
  contextInfo,
}) {
  const validSignature = await verifyBytes(peerSigningPublicKeyRaw, peerSignedPreKeyPublicRaw, peerSignedPreKeySignature);
  if (!validSignature) throw new Error("Invalid signed prekey signature");

  const validPqSignature = await verifyBytes(peerSigningPublicKeyRaw, peerPqPreKeyPublic, peerPqPreKeySignature);
  if (!validPqSignature) throw new Error("Invalid PQ prekey signature");

  const dh1 = await dh(identityPrivateKey, peerSignedPreKeyPublicRaw);
  const dh2 = await dh(ephemeralPrivateKey, peerIdentityPublicKeyRaw);
  const dh3 = await dh(ephemeralPrivateKey, peerSignedPreKeyPublicRaw);
  const dh4 = peerOneTimePreKeyPublicRaw ? await dh(ephemeralPrivateKey, peerOneTimePreKeyPublicRaw) : new Uint8Array();
  const { cipherText: pqCipherText, sharedSecret: pqSharedSecret } = pqEncapsulate(peerPqPreKeyPublic);

  const secret = await x3dhRootSecret(
    [dh1, dh2, dh3, dh4],
    pqSharedSecret,
    contextInfo,
    identityPublicKeyRaw, // we are the initiator
    peerIdentityPublicKeyRaw
  );
  return { secret, pqCipherText };
}

/**
 * @param {object} params
 * @param {CryptoKey} params.identityPrivateKey - our long-term X25519 identity private key
 * @param {Uint8Array} params.identityPublicKeyRaw - our long-term X25519 identity public key (raw)
 * @param {CryptoKey} params.signedPreKeyPrivateKey - the signed prekey's private key the initiator used
 * @param {Uint8Array} params.peerIdentityPublicKeyRaw - initiator's long-term X25519 identity public key
 * @param {Uint8Array} params.peerEphemeralPublicKeyRaw - initiator's fresh ephemeral public key
 * @param {Uint8Array} params.pqPreKeySecretKey - our ML-KEM-768 PQ prekey's secret key (from generatePqPreKeyPair)
 * @param {Uint8Array} params.pqCipherText - the ML-KEM ciphertext the initiator sent alongside their handshake metadata
 * @param {CryptoKey|null} [params.oneTimePreKeyPrivateKey] - our one-time prekey's private key, if the initiator used one
 * @param {string} params.contextInfo - must match the initiator's contextInfo exactly
 * @returns {Promise<Uint8Array>} 32-byte shared secret, identical to the initiator's if both sides agree
 */
export async function deriveSecretAsRecipient({
  identityPrivateKey,
  identityPublicKeyRaw,
  signedPreKeyPrivateKey,
  peerIdentityPublicKeyRaw,
  peerEphemeralPublicKeyRaw,
  pqPreKeySecretKey,
  pqCipherText,
  oneTimePreKeyPrivateKey = null,
  contextInfo,
}) {
  const dh1 = await dh(signedPreKeyPrivateKey, peerIdentityPublicKeyRaw);
  const dh2 = await dh(identityPrivateKey, peerEphemeralPublicKeyRaw);
  const dh3 = await dh(signedPreKeyPrivateKey, peerEphemeralPublicKeyRaw);
  const dh4 = oneTimePreKeyPrivateKey ? await dh(oneTimePreKeyPrivateKey, peerEphemeralPublicKeyRaw) : new Uint8Array();
  const pqSharedSecret = pqDecapsulate(pqCipherText, pqPreKeySecretKey);

  return x3dhRootSecret(
    [dh1, dh2, dh3, dh4],
    pqSharedSecret,
    contextInfo,
    peerIdentityPublicKeyRaw, // the peer initiated
    identityPublicKeyRaw
  );
}
