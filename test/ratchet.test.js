import test from "node:test";
import assert from "node:assert/strict";
import {
  bytes,
  text,
  base64ToUint8,
  uint8ToBase64,
  exportRawPublic,
  generateDhKeyPair,
  generateSigningKeyPair,
  signBytes,
} from "../src/primitives.js";
import { deriveSecretAsInitiator, deriveSecretAsRecipient, generatePqPreKeyPair } from "../src/x3dh.js";
import { DoubleRatchetSession } from "../src/ratchet.js";

const CONTEXT = "test-session-1";

async function createParty() {
  const identity = await generateDhKeyPair();
  const signing = await generateSigningKeyPair();
  const signedPreKey = await generateDhKeyPair();
  const signedPreKeyPublicRaw = await exportRawPublic(signedPreKey.publicKey);
  const signature = await signBytes(signing.privateKey, signedPreKeyPublicRaw);
  const pqPreKey = generatePqPreKeyPair();
  const pqPreKeySignature = await signBytes(signing.privateKey, pqPreKey.publicKey);
  return {
    identity,
    signedPreKey,
    pqPreKey,
    identityPublicRaw: await exportRawPublic(identity.publicKey),
    signingPublicRaw: await exportRawPublic(signing.publicKey),
    signedPreKeyPublicRaw,
    signedPreKeySignature: signature,
    pqPreKeySignature,
  };
}

async function handshake(alice, bob) {
  const ephemeral = await generateDhKeyPair();
  const ephemeralPublicRaw = await exportRawPublic(ephemeral.publicKey);

  const { secret: aliceSecret, pqCipherText } = await deriveSecretAsInitiator({
    identityPrivateKey: alice.identity.privateKey,
    ephemeralPrivateKey: ephemeral.privateKey,
    peerIdentityPublicKeyRaw: bob.identityPublicRaw,
    peerSignedPreKeyPublicRaw: bob.signedPreKeyPublicRaw,
    peerSignedPreKeySignature: bob.signedPreKeySignature,
    peerSigningPublicKeyRaw: bob.signingPublicRaw,
    peerPqPreKeyPublic: bob.pqPreKey.publicKey,
    peerPqPreKeySignature: bob.pqPreKeySignature,
    contextInfo: CONTEXT,
  });

  const bobSecret = await deriveSecretAsRecipient({
    identityPrivateKey: bob.identity.privateKey,
    signedPreKeyPrivateKey: bob.signedPreKey.privateKey,
    peerIdentityPublicKeyRaw: alice.identityPublicRaw,
    peerEphemeralPublicKeyRaw: ephemeralPublicRaw,
    pqPreKeySecretKey: bob.pqPreKey.secretKey,
    pqCipherText,
    contextInfo: CONTEXT,
  });

  assert.deepStrictEqual(aliceSecret, bobSecret, "both sides must derive the same PQXDH secret");

  const aliceSession = new DoubleRatchetSession();
  await aliceSession.initAsInitiator(aliceSecret, bob.signedPreKeyPublicRaw, bob.pqPreKey.publicKey);

  const bobSession = new DoubleRatchetSession();
  await bobSession.initAsRecipient(bobSecret, {
    initialRatchetKeyPair: bob.signedPreKey,
    initialRatchetPublic: bob.signedPreKeyPublicRaw,
    initialPqRatchetKeyPair: bob.pqPreKey,
    remoteRatchetPublic: aliceSession.localRatchetPublic,
    remotePqRatchetPublic: aliceSession.localPqRatchet.publicKey,
    remotePqCipherText: aliceSession.pqCtToSend,
  });

  return { aliceSession, bobSession };
}

test("X3DH signature check rejects a tampered signed prekey", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const ephemeral = await generateDhKeyPair();

  await assert.rejects(
    () =>
      deriveSecretAsInitiator({
        identityPrivateKey: alice.identity.privateKey,
        ephemeralPrivateKey: ephemeral.privateKey,
        peerIdentityPublicKeyRaw: bob.identityPublicRaw,
        peerSignedPreKeyPublicRaw: bob.signedPreKeyPublicRaw,
        peerSignedPreKeySignature: alice.signedPreKeySignature, // wrong signature
        peerSigningPublicKeyRaw: bob.signingPublicRaw,
        peerPqPreKeyPublic: bob.pqPreKey.publicKey,
        peerPqPreKeySignature: bob.pqPreKeySignature,
        contextInfo: CONTEXT,
      }),
    /Invalid signed prekey signature/
  );
});

test("PQXDH signature check rejects a tampered PQ prekey", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const ephemeral = await generateDhKeyPair();

  await assert.rejects(
    () =>
      deriveSecretAsInitiator({
        identityPrivateKey: alice.identity.privateKey,
        ephemeralPrivateKey: ephemeral.privateKey,
        peerIdentityPublicKeyRaw: bob.identityPublicRaw,
        peerSignedPreKeyPublicRaw: bob.signedPreKeyPublicRaw,
        peerSignedPreKeySignature: bob.signedPreKeySignature,
        peerSigningPublicKeyRaw: bob.signingPublicRaw,
        peerPqPreKeyPublic: bob.pqPreKey.publicKey,
        peerPqPreKeySignature: alice.pqPreKeySignature, // wrong signature
        contextInfo: CONTEXT,
      }),
    /Invalid PQ prekey signature/
  );
});

test("handshake + first message roundtrip", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const frame = await aliceSession.encrypt(bytes("hello bob"));
  const plaintext = await bobSession.decrypt(frame);
  assert.equal(text(plaintext), "hello bob");
});

function containsSubarray(haystack, needle) {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

test("the wire frame is a single Uint8Array carrying no plaintext routing metadata", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession } = await handshake(alice, bob);

  const frame = await aliceSession.encrypt(bytes("hello"));
  assert.ok(frame instanceof Uint8Array);
  // The ratchet public keys and KEM ciphertext ride inside the encrypted header -- none of
  // their bytes may appear verbatim anywhere in the frame.
  assert.equal(containsSubarray(frame, aliceSession.localRatchetPublic), false);
  assert.equal(containsSubarray(frame, aliceSession.localPqRatchet.publicKey), false);
  assert.equal(containsSubarray(frame, aliceSession.pqCtToSend), false);
});

test("frames are constant-size for equal plaintexts, ratchet step or not", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const a0 = await aliceSession.encrypt(bytes("same length!"));
  const a1 = await aliceSession.encrypt(bytes("same length!")); // same chain, no ratchet
  assert.equal(text(await bobSession.decrypt(a0)), "same length!");
  assert.equal(text(await bobSession.decrypt(a1)), "same length!");

  const b0 = await bobSession.encrypt(bytes("same length!")); // Bob's first send -- fresh ratchet keys
  assert.equal(text(await aliceSession.decrypt(b0)), "same length!");

  // A length-observer must not be able to tell ratchet-carrying frames from ordinary ones.
  assert.equal(a0.length, a1.length);
  assert.equal(a0.length, b0.length);
});

function flipByte(frame, offset) {
  const copy = frame.slice();
  copy[offset] ^= 0xff;
  return copy;
}

test("a tampered header ciphertext fails to decrypt", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const frame = await aliceSession.encrypt(bytes("hello"));
  await assert.rejects(() => bobSession.decrypt(flipByte(frame, 12))); // first header-ciphertext byte
});

test("out-of-order delivery within one chain uses the skipped-key cache", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const messages = ["msg-0", "msg-1", "msg-2"];
  const frames = [];
  for (const m of messages) frames.push(await aliceSession.encrypt(bytes(m)));

  // deliver out of order: 2, then 0, then 1
  for (const i of [2, 0, 1]) {
    const plaintext = await bobSession.decrypt(frames[i]);
    assert.equal(text(plaintext), messages[i]);
  }
});

test("a late message from a chain already superseded by a DH ratchet still decrypts", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  // Alice sends two messages; only the first is delivered to Bob right away.
  const a0 = await aliceSession.encrypt(bytes("a0"));
  const a1 = await aliceSession.encrypt(bytes("a1")); // delayed -- delivered late, below
  assert.equal(text(await bobSession.decrypt(a0)), "a0");

  // Bob replies -- this is what causes Alice to DH-ratchet forward.
  const b0 = await bobSession.encrypt(bytes("b0"));
  assert.equal(text(await aliceSession.decrypt(b0)), "b0");

  // Alice's next message now carries a brand new ratchet key.
  const a2 = await aliceSession.encrypt(bytes("a2"));
  assert.equal(text(await bobSession.decrypt(a2)), "a2"); // forces Bob to ratchet too

  // The still-delayed a1, from the now-superseded chain, must still decrypt --
  // and must NOT cause Bob to ratchet backward.
  assert.equal(text(await bobSession.decrypt(a1)), "a1");
});

test("a message skipped two ratchet generations ago is still recoverable", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const a0 = await aliceSession.encrypt(bytes("a0"));
  const a1 = await aliceSession.encrypt(bytes("a1")); // delayed until the very end
  assert.equal(text(await bobSession.decrypt(a0)), "a0");

  const b0 = await bobSession.encrypt(bytes("b0"));
  assert.equal(text(await aliceSession.decrypt(b0)), "b0"); // Alice's 1st ratchet

  const a2 = await aliceSession.encrypt(bytes("a2"));
  assert.equal(text(await bobSession.decrypt(a2)), "a2"); // Bob's 1st ratchet of Alice's key -- a1 cached here

  const b1 = await bobSession.encrypt(bytes("b1"));
  assert.equal(text(await aliceSession.decrypt(b1)), "b1"); // Alice's 2nd ratchet

  const a3 = await aliceSession.encrypt(bytes("a3"));
  assert.equal(text(await bobSession.decrypt(a3)), "a3"); // Bob's 2nd ratchet of Alice's key

  // a1 is now two ratchet generations behind Bob's current chain -- only the skip-cache's
  // header-key trial decryption can still recover it.
  assert.equal(text(await bobSession.decrypt(a1)), "a1");
});

test("replaying an already-consumed message key fails instead of succeeding twice", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const frame = await aliceSession.encrypt(bytes("only once"));
  assert.equal(text(await bobSession.decrypt(frame)), "only once");
  await assert.rejects(() => bobSession.decrypt(frame));
});

test("skip count exceeding maxSkip throws instead of growing unbounded", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);
  bobSession.maxSkip = 5;

  let lastFrame;
  for (let i = 0; i < 10; i++) lastFrame = await aliceSession.encrypt(bytes(`m${i}`));

  await assert.rejects(() => bobSession.decrypt(lastFrame), /Too many skipped messages/);
});

// --- commit-only-after-authentication regression tests ---
// A valid header only proves knowledge of a header key, not body authenticity. An on-path
// attacker replaying a legitimate frame with a bit-flipped body must not consume the real
// message's key, evict its skip-cache entry, or force a ratchet step -- the Double Ratchet
// spec's "state is only updated if decryption succeeds" requirement.

function tamperBody(frame) {
  return flipByte(frame, frame.length - 1); // last body-ciphertext byte -- inside the GCM tag
}

test("a tampered body does not burn the message key -- the real frame still decrypts", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const frame = await aliceSession.encrypt(bytes("the real message"));
  await assert.rejects(() => bobSession.decrypt(tamperBody(frame)));
  assert.equal(text(await bobSession.decrypt(frame)), "the real message");
});

test("a tampered ratchet-carrying body does not advance the ratchet or desync the session", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  assert.equal(text(await bobSession.decrypt(await aliceSession.encrypt(bytes("a0")))), "a0");
  const b0 = await bobSession.encrypt(bytes("b0")); // carries Bob's fresh ratchet keys

  // Attacker injects the tampered copy first -- decrypting it hits Alice's viaNext/_advance
  // path, which must fully roll back when the body's auth tag check fails.
  await assert.rejects(() => aliceSession.decrypt(tamperBody(b0)));
  assert.equal(text(await aliceSession.decrypt(b0)), "b0");

  // And the conversation still works in both directions afterward.
  assert.equal(text(await bobSession.decrypt(await aliceSession.encrypt(bytes("a1")))), "a1");
  assert.equal(text(await aliceSession.decrypt(await bobSession.encrypt(bytes("b1")))), "b1");
});

test("a tampered body does not evict a skipped message's cached key", async () => {
  const alice = await createParty();
  const bob = await createParty();
  const { aliceSession, bobSession } = await handshake(alice, bob);

  const a0 = await aliceSession.encrypt(bytes("a0")); // delayed -- its key lands in the skip cache
  const a1 = await aliceSession.encrypt(bytes("a1"));
  assert.equal(text(await bobSession.decrypt(a1)), "a1"); // skips over a0, caching its key

  await assert.rejects(() => bobSession.decrypt(tamperBody(a0)));
  assert.equal(text(await bobSession.decrypt(a0)), "a0");
});
