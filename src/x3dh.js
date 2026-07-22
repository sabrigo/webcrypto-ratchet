// X3DH (Extended Triple Diffie-Hellman) key agreement, generalized from the Signal design:
// four ECDH exchanges (identity/signed-prekey/ephemeral/one-time-prekey combinations) folded
// through HKDF into a single 32-byte shared secret, with the signed prekey's signature checked
// before it's ever used. Callers pass already-decoded CryptoKey/Uint8Array material -- this
// module has no opinion on wire format (base64, JSON shape, etc.), that's the caller's job.
import { dh, hkdf, sha256, bytes, concatBytes, verifyBytes } from "./primitives.js";

async function x3dhRootSecret(dhOutputs, contextInfo) {
  const salt = await sha256(bytes(`x3dh-v1:${contextInfo}`));
  return hkdf(concatBytes(...dhOutputs), salt, bytes("webcrypto-ratchet-x3dh-root"), 32);
}

/**
 * @param {object} params
 * @param {CryptoKey} params.identityPrivateKey - our long-term ECDH identity private key
 * @param {CryptoKey} params.ephemeralPrivateKey - a fresh ECDH keypair's private key, generated for this handshake
 * @param {Uint8Array} params.peerIdentityPublicKeyRaw - peer's long-term ECDH identity public key
 * @param {Uint8Array} params.peerSignedPreKeyPublicRaw - peer's published signed prekey (ECDH public)
 * @param {Uint8Array} params.peerSignedPreKeySignature - signature over peerSignedPreKeyPublicRaw
 * @param {Uint8Array} params.peerSigningPublicKeyRaw - peer's long-term ECDSA signing public key
 * @param {Uint8Array|null} [params.peerOneTimePreKeyPublicRaw] - peer's one-time prekey, if one was available
 * @param {string} params.contextInfo - caller-supplied domain-separation string (e.g. a session/room id)
 * @returns {Promise<Uint8Array>} 32-byte shared secret to seed the Double Ratchet
 */
export async function deriveSecretAsInitiator({
  identityPrivateKey,
  ephemeralPrivateKey,
  peerIdentityPublicKeyRaw,
  peerSignedPreKeyPublicRaw,
  peerSignedPreKeySignature,
  peerSigningPublicKeyRaw,
  peerOneTimePreKeyPublicRaw = null,
  contextInfo,
}) {
  const validSignature = await verifyBytes(peerSigningPublicKeyRaw, peerSignedPreKeyPublicRaw, peerSignedPreKeySignature);
  if (!validSignature) throw new Error("Invalid signed prekey signature");

  const dh1 = await dh(identityPrivateKey, peerSignedPreKeyPublicRaw);
  const dh2 = await dh(ephemeralPrivateKey, peerIdentityPublicKeyRaw);
  const dh3 = await dh(ephemeralPrivateKey, peerSignedPreKeyPublicRaw);
  const dh4 = peerOneTimePreKeyPublicRaw ? await dh(ephemeralPrivateKey, peerOneTimePreKeyPublicRaw) : new Uint8Array();

  return x3dhRootSecret([dh1, dh2, dh3, dh4], contextInfo);
}

/**
 * @param {object} params
 * @param {CryptoKey} params.identityPrivateKey - our long-term ECDH identity private key
 * @param {CryptoKey} params.signedPreKeyPrivateKey - the signed prekey's private key the initiator used
 * @param {Uint8Array} params.peerIdentityPublicKeyRaw - initiator's long-term ECDH identity public key
 * @param {Uint8Array} params.peerEphemeralPublicKeyRaw - initiator's fresh ephemeral public key
 * @param {CryptoKey|null} [params.oneTimePreKeyPrivateKey] - our one-time prekey's private key, if the initiator used one
 * @param {string} params.contextInfo - must match the initiator's contextInfo exactly
 * @returns {Promise<Uint8Array>} 32-byte shared secret, identical to the initiator's if both sides agree
 */
export async function deriveSecretAsRecipient({
  identityPrivateKey,
  signedPreKeyPrivateKey,
  peerIdentityPublicKeyRaw,
  peerEphemeralPublicKeyRaw,
  oneTimePreKeyPrivateKey = null,
  contextInfo,
}) {
  const dh1 = await dh(signedPreKeyPrivateKey, peerIdentityPublicKeyRaw);
  const dh2 = await dh(identityPrivateKey, peerEphemeralPublicKeyRaw);
  const dh3 = await dh(signedPreKeyPrivateKey, peerEphemeralPublicKeyRaw);
  const dh4 = oneTimePreKeyPrivateKey ? await dh(oneTimePreKeyPrivateKey, peerEphemeralPublicKeyRaw) : new Uint8Array();

  return x3dhRootSecret([dh1, dh2, dh3, dh4], contextInfo);
}
