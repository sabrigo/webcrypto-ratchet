// Byte/base64 helpers, ECDH/ECDSA key operations, DER<->raw P-256 signature conversion,
// and HKDF/HMAC/SHA-256 wrappers -- all built on the standard WebCrypto API (crypto.subtle).
// No networking, no protocol logic here; see x3dh.js and ratchet.js for that.

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

function trimLeadingZeroes(value) {
  let offset = 0;
  while (offset < value.length - 1 && value[offset] === 0) offset++;
  return value.slice(offset);
}

function leftPadP256Integer(value) {
  const trimmed = trimLeadingZeroes(value);
  if (trimmed.length > 32) throw new Error("Invalid P-256 signature integer");
  const out = new Uint8Array(32);
  out.set(trimmed, 32 - trimmed.length);
  return out;
}

function derIntegerFromP256(value) {
  let integer = trimLeadingZeroes(value);
  if (integer[0] & 0x80) integer = concatBytes(new Uint8Array([0]), integer);
  return concatBytes(new Uint8Array([0x02, integer.length]), integer);
}

// WebCrypto's ECDSA sign/verify uses the raw (r||s) IEEE P1363 format, but some peers may hand
// you DER-encoded signatures (or vice versa) -- these two converters let verifyBytes() accept
// either without the caller needing to know which one it got.
export function rawP256SignatureToDer(signature) {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error("Invalid raw P-256 signature");
  }
  const r = derIntegerFromP256(signature.slice(0, 32));
  const s = derIntegerFromP256(signature.slice(32, 64));
  return concatBytes(new Uint8Array([0x30, r.length + s.length]), r, s);
}

export function derP256SignatureToRaw(signature) {
  if (!(signature instanceof Uint8Array) || signature.length < 8 || signature[0] !== 0x30 || signature[1] !== signature.length - 2) {
    throw new Error("Invalid DER P-256 signature");
  }
  let offset = 2;
  if (signature[offset++] !== 0x02) throw new Error("Invalid DER P-256 signature");
  const rLength = signature[offset++];
  const r = signature.slice(offset, offset + rLength);
  offset += rLength;
  if (signature[offset++] !== 0x02) throw new Error("Invalid DER P-256 signature");
  const sLength = signature[offset++];
  const s = signature.slice(offset, offset + sLength);
  if (offset + sLength !== signature.length) throw new Error("Invalid DER P-256 signature");
  return concatBytes(leftPadP256Integer(r), leftPadP256Integer(s));
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
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

export async function generateSigningKeyPair() {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

export async function exportRawPublic(key) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

export async function exportPrivateJwk(key) {
  return crypto.subtle.exportKey("jwk", key);
}

export async function importDhPublic(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

export async function importDhPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

export async function importSigningPublic(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

export async function importSigningPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
}

export async function dh(privateKey, publicKeyRaw) {
  const publicKey = await importDhPublic(publicKeyRaw);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));
}

export async function signBytes(privateKey, message) {
  return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, message));
}

export async function verifyBytes(publicKeyRaw, message, signature) {
  const publicKey = await importSigningPublic(publicKeyRaw);
  const candidates = [signature];
  try {
    const raw = derP256SignatureToRaw(signature);
    if (!candidates.some((candidate) => equalBytes(candidate, raw))) candidates.push(raw);
  } catch {}
  try {
    const der = rawP256SignatureToDer(signature);
    if (!candidates.some((candidate) => equalBytes(candidate, der))) candidates.push(der);
  } catch {}

  for (const candidate of candidates) {
    try {
      if (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, candidate, message)) {
        return true;
      }
    } catch {}
  }
  return false;
}
