// Byte/base64 helpers, X25519/Ed25519 key operations, and HKDF/HMAC/SHA-256 wrappers -- all
// built on the standard WebCrypto API (crypto.subtle). No networking, no protocol logic here;
// see x3dh.js and ratchet.js for that.

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

export function bytes(value) {
  return TEXT_ENCODER.encode(value);
}

export function text(value) {
  return TEXT_DECODER.decode(value);
}

export function uint8ToBase64(u8) {
  let binary = "";
  for (let i = 0; i < u8.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function base64ToUint8(value) {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function concatBytes(...chunks) {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function hmac(keyBytes, messageBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, messageBytes));
}

export async function hkdf(secretBytes, saltBytes, infoBytes, byteLength) {
  const key = await crypto.subtle.importKey("raw", secretBytes, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: infoBytes },
      key,
      byteLength * 8
    )
  );
}

export async function generateDhKeyPair() {
  return crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
}

export async function generateSigningKeyPair() {
  return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
}

export async function exportRawPublic(key) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

export async function exportPrivateJwk(key) {
  return crypto.subtle.exportKey("jwk", key);
}

export async function importDhPublic(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "X25519" }, false, []);
}

export async function importDhPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "X25519" }, true, ["deriveBits"]);
}

export async function importSigningPublic(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

export async function importSigningPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["sign"]);
}

export async function dh(privateKey, publicKeyRaw) {
  const publicKey = await importDhPublic(publicKeyRaw);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256));
}

export async function signBytes(privateKey, message) {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, message));
}

export async function verifyBytes(publicKeyRaw, message, signature) {
  const publicKey = await importSigningPublic(publicKeyRaw);
  try {
    return await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, message);
  } catch {
    return false;
  }
}
