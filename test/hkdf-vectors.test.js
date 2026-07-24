// Cross-implementation check for the one primitive with a real spec to check against: our
// hkdf() (WebCrypto/crypto.subtle) is diffed against node:crypto's independent HKDF-SHA256
// (OpenSSL-backed), including RFC 5869's own Test Case 1 inputs. A KDF/domain-separation bug
// that's merely self-consistent (what round-trip tests can't catch) would show up as a mismatch
// here.
import test from "node:test";
import assert from "node:assert/strict";
import { hkdfSync } from "node:crypto";
import { hkdf } from "../src/primitives.js";

function referenceHkdf(ikm, salt, info, length) {
  return new Uint8Array(hkdfSync("sha256", Buffer.from(ikm), Buffer.from(salt), Buffer.from(info), length));
}

test("hkdf matches node:crypto's independent HKDF-SHA256 (RFC 5869 Test Case 1 inputs)", async () => {
  const ikm = Uint8Array.from(Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex"));
  const salt = Uint8Array.from(Buffer.from("000102030405060708090a0b0c", "hex"));
  const info = Uint8Array.from(Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex"));

  const actual = await hkdf(ikm, salt, info, 42);
  const expected = referenceHkdf(ikm, salt, info, 42);
  assert.deepStrictEqual(actual, expected);
});

test("hkdf matches node:crypto across random inputs and lengths", async () => {
  for (const length of [16, 32, 64, 96]) {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const info = crypto.getRandomValues(new Uint8Array(8));

    const actual = await hkdf(ikm, salt, info, length);
    const expected = referenceHkdf(ikm, salt, info, length);
    assert.deepStrictEqual(actual, expected);
  }
});
