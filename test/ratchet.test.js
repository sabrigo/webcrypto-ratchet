import test from "node:test";
import assert from "node:assert/strict";
import {
  bytes,
  text,
  exportRawPublic,
  generateDhKeyPair,
  generateSigningKeyPair,
  signBytes,
} from "../src/primitives.js";
import { deriveSecretAsInitiator, deriveSecretAsRecipient } from "../src/x3dh.js";
import { DoubleRatchetSession } from "../src/ratchet.js";

const CONTEXT = "test-session-1";

async function createParty() {
  const identity = await generateDhKeyPair();
  const signing = await generateSigningKeyPair();
  const signedPreKey = await generateDhKeyPair();
  const signedPreKeyPublicRaw = await exportRawPublic(signedPreKey.publicKey);
  const signature = await signBytes(signing.privateKey, signedPreKeyPublicRaw);
  return {
    identity,
    signedPreKey,
    identityPublicRaw: await exportRawPublic(identity.publicKey),
    signingPublicRaw: await exportRawPublic(signing.publicKey),
    signedPreKeyPublicRaw,
    signedPreKeySignature: signature,
  };
}

async function handshake(alice, bob) {
  const ephemeral = await generateDhKeyPair();
  const ephemeralPublicRaw = await exportRawPublic(ephemeral.publicKey);

  const aliceSecret = await deriveSecretAsInitiator({
    identityPrivateKey: alice.identity.privateKey,
    ephemeralPrivateKey: ephemeral.privateKey,
    peerIdentityPublicKeyRaw: bob.identityPublicRaw,
    peerSignedPreKeyPublicRaw: bob.signedPreKeyPublicRaw,
    peerSignedPreKeySignature: bob.signedPreKeySignature,
    peerSigningPublicKeyRaw: bob.signingPublicRaw,
    contextInfo: CONTEXT,
  });

  const bobSecret = await deriveSecretAsRecipient({
    identityPrivateKey: bob.identity.privateKey,
    signedPreKeyPrivateKey: bob.signedPreKey.privateKey,
    peerIdentityPublicKeyRaw: alice.identityPublicRaw,
    peerEphemeralPublicKeyRaw: ephemeralPublicRaw,
    contextInfo: CONTEXT,
  });

  assert.deepStrictEqual(aliceSecret, bobSecret, "both sides must derive the same X3DH secret");

  const aliceSession = new DoubleRatchetSession();
  await aliceSession.initAsInitiator(aliceSecret, bob.signedPreKeyPublicRaw);

  const bobSession = new DoubleRatchetSession();
  await bobSession.initAsRecipient(bobSecret, {
    initialRatchetKeyPair: bob.signedPreKey,
    initialRatchetPublic: bob.signedPreKeyPublicRaw,
    remoteRatchetPublic: aliceSession.localRatchetPublic,
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
        contextInfo: CONTEXT,
      }),
    /Invalid signed prekey signature/
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
  assert.notEqual(a2.dh, a0.dh, "a2 should be on a new ratchet chain");
  assert.equal(text(await bobSession.decrypt(a2)), "a2"); // forces Bob to ratchet too

  // The still-delayed a1, from the now-superseded chain, must still decrypt --
  // and must NOT cause Bob to ratchet backward.
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
