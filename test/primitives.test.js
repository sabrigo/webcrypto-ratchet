import test from "node:test";
import assert from "node:assert/strict";
import {
  bytes,
  text,
  base64ToUint8,
  uint8ToBase64,
  concatBytes,
  equalBytes,
  sha256,
  hmac,
  hkdf,
  generateDhKeyPair,
  generateSigningKeyPair,
  exportRawPublic,
  exportPrivateJwk,
  importDhPrivate,
  importSigningPrivate,
  dh,
  signBytes,
  verifyBytes,
} from "../src/primitives.js";

test("bytes/text round-trip a UTF-8 string", () => {
  assert.equal(text(bytes("hello ☃")), "hello ☃");
});

test("base64 round-trips arbitrary bytes, including a chunk-boundary length", () => {
  const original = crypto.getRandomValues(new Uint8Array(0x8000 + 10));
  assert.deepStrictEqual(base64ToUint8(uint8ToBase64(original)), original);
});

test("concatBytes joins chunks in order", () => {
  assert.deepStrictEqual(
    concatBytes(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3])),
    new Uint8Array([1, 2, 3])
  );
});

test("equalBytes compares content, rejects length/nullish mismatches", () => {
  assert.equal(equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
  assert.equal(equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  assert.equal(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
  assert.equal(equalBytes(null, new Uint8Array([1])), false);
  assert.equal(equalBytes(new Uint8Array([1]), undefined), false);
});

test("sha256 and hmac produce deterministic 32-byte outputs", async () => {
  const digest = await sha256(bytes("data"));
  assert.equal(digest.length, 32);
  assert.deepStrictEqual(digest, await sha256(bytes("data")));

  const mac = await hmac(bytes("key"), bytes("message"));
  assert.equal(mac.length, 32);
  assert.deepStrictEqual(mac, await hmac(bytes("key"), bytes("message")));
});

test("hkdf derives the requested length and varies with info", async () => {
  const secret = bytes("secret-input-material");
  const salt = bytes("salt");
  const a = await hkdf(secret, salt, bytes("context-a"), 32);
  const b = await hkdf(secret, salt, bytes("context-b"), 32);
  assert.equal(a.length, 32);
  assert.notDeepStrictEqual(a, b);
});

test("DH private/public JWK export and re-import reproduces the same shared secret", async () => {
  const alice = await generateDhKeyPair();
  const bob = await generateDhKeyPair();
  const bobPublicRaw = await exportRawPublic(bob.publicKey);

  const aliceJwk = await exportPrivateJwk(alice.privateKey);
  const aliceReimported = await importDhPrivate(aliceJwk);

  assert.deepStrictEqual(await dh(alice.privateKey, bobPublicRaw), await dh(aliceReimported, bobPublicRaw));
});

test("verifyBytes accepts a genuine signature and rejects a tampered one", async () => {
  const signing = await generateSigningKeyPair();
  const message = bytes("payload");
  const signature = await signBytes(signing.privateKey, message);
  const publicRaw = await exportRawPublic(signing.publicKey);

  assert.equal(await verifyBytes(publicRaw, message, signature), true);
  assert.equal(await verifyBytes(publicRaw, bytes("tampered"), signature), false);
});

test("verifyBytes returns false instead of throwing on a malformed signature", async () => {
  const signing = await generateSigningKeyPair();
  const publicRaw = await exportRawPublic(signing.publicKey);
  assert.equal(await verifyBytes(publicRaw, bytes("payload"), new Uint8Array(3)), false);
});

test("signing private JWK export and re-import produces a signature the original public key verifies", async () => {
  const signing = await generateSigningKeyPair();
  const publicRaw = await exportRawPublic(signing.publicKey);
  const reimported = await importSigningPrivate(await exportPrivateJwk(signing.privateKey));
  const message = bytes("payload");

  assert.equal(await verifyBytes(publicRaw, message, await signBytes(reimported, message)), true);
});
