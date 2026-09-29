import {
  generateDhKeyPair, generateSigningKeyPair, generatePqPreKeyPair,
  exportRawPublic, signBytes, deriveSecretAsInitiator, deriveSecretAsRecipient,
  DoubleRatchetSession, bytes, text
} from "https://esm.sh/webcrypto-ratchet@0.7.2?bundle";

const $ = id => document.getElementById(id);
const run = $("run"), logEl = $("log"), messagesEl = $("messages");

function log(message) {
  logEl.textContent += (logEl.textContent ? "\n" : "") + message;
  logEl.scrollTop = logEl.scrollHeight;
}
function setStep(n, state = "active") {
  for (let i = 1; i <= 4; i++) {
    const el = $("step-" + i);
    el.classList.toggle("active", i === n && state === "active");
    el.classList.toggle("done", i < n || (i === n && state === "done"));
  }
}
function hexPreview(value, length = 12) {
  return Array.from(value.slice(0, length)).map(x => x.toString(16).padStart(2, "0")).join("") + "…";
}
function setStats(id, values) {
  $(id).innerHTML = values.map(([k, v]) => "<dt>" + k + "</dt><dd>" + v + "</dd>").join("");
}
function addMessage(who, direction, content) {
  const empty = messagesEl.querySelector(".empty");
  if (empty) empty.remove();
  const div = document.createElement("div");
  div.className = "message " + (who === "Alice" ? "alice-msg" : "bob-msg");
  const label = document.createElement("small");
  label.textContent = who + " · " + direction;
  div.append(label, document.createTextNode(content));
  messagesEl.appendChild(div);
}

async function main() {
  run.disabled = true; logEl.textContent = ""; messagesEl.innerHTML = "";
  setStep(1);
  $("alice-status").textContent = "Generating identity and prekeys…";
  $("bob-status").textContent = "Generating identity and prekeys…";
  log("Starting entirely local browser demo…");

  const bobIdentity = await generateDhKeyPair();
  const bobIdentityPublic = await exportRawPublic(bobIdentity.publicKey);
  const bobSigning = await generateSigningKeyPair();
  const bobSigningPublic = await exportRawPublic(bobSigning.publicKey);
  const bobSignedPreKey = await generateDhKeyPair();
  const bobSignedPreKeyPublic = await exportRawPublic(bobSignedPreKey.publicKey);
  const bobSignedPreKeySignature = await signBytes(bobSigning.privateKey, bobSignedPreKeyPublic);
  const bobPqPreKey = generatePqPreKeyPair();
  const bobPqPreKeySignature = await signBytes(bobSigning.privateKey, bobPqPreKey.publicKey);

  const aliceIdentity = await generateDhKeyPair();
  const aliceIdentityPublic = await exportRawPublic(aliceIdentity.publicKey);
  const aliceEphemeral = await generateDhKeyPair();
  const aliceEphemeralPublic = await exportRawPublic(aliceEphemeral.publicKey);

  setStats("alice-stats", [["Identity","X25519"],["Signing","Ed25519"],["Ratchet","X25519 + ML-KEM-768"],["Header","AES-256-GCM"],["Message KDF","HMAC-SHA256"]]);
  setStats("bob-stats", [["Identity","X25519"],["Signing","Ed25519"],["Ratchet","X25519 + ML-KEM-768"],["Header","AES-256-GCM"],["Message KDF","HMAC-SHA256"]]);
  $("alice-status").textContent = "Keys ready"; $("bob-status").textContent = "Prekeys published";
  setStep(1, "done");

  setStep(2);
  log("Bob published a signed X25519 prekey + signed ML-KEM-768 prekey.");
  const { secret: aliceSecret, pqCipherText } = await deriveSecretAsInitiator({
    identityPrivateKey: aliceIdentity.privateKey, identityPublicKeyRaw: aliceIdentityPublic,
    ephemeralPrivateKey: aliceEphemeral.privateKey,
    peerIdentityPublicKeyRaw: bobIdentityPublic,
    peerSignedPreKeyPublicRaw: bobSignedPreKeyPublic,
    peerSignedPreKeySignature: bobSignedPreKeySignature,
    peerSigningPublicKeyRaw: bobSigningPublic,
    peerPqPreKeyPublic: bobPqPreKey.publicKey,
    peerPqPreKeySignature: bobPqPreKeySignature,
    contextInfo: "browser-demo"
  });
  const bobSecret = await deriveSecretAsRecipient({
    identityPrivateKey: bobIdentity.privateKey, identityPublicKeyRaw: bobIdentityPublic,
    signedPreKeyPrivateKey: bobSignedPreKey.privateKey,
    peerIdentityPublicKeyRaw: aliceIdentityPublic,
    peerEphemeralPublicKeyRaw: aliceEphemeralPublic,
    pqPreKeySecretKey: bobPqPreKey.secretKey, pqCipherText,
    contextInfo: "browser-demo"
  });
  const secretsMatch = aliceSecret.length === bobSecret.length &&
    aliceSecret.every((v, i) => v === bobSecret[i]);
  if (!secretsMatch) throw new Error("PQXDH shared secrets did not match.");
  log("PQXDH complete — both sides derived the same 32-byte root secret (" + hexPreview(aliceSecret) + ").");
  setStep(2, "done");

  setStep(3);
  const alice = new DoubleRatchetSession({ associatedDataPrefix: "browser-demo" });
  const bob = new DoubleRatchetSession({ associatedDataPrefix: "browser-demo" });
  await alice.initAsInitiator(aliceSecret, bobSignedPreKeyPublic, bobPqPreKey.publicKey);
  await bob.initAsRecipient(bobSecret, {
    initialRatchetKeyPair: bobSignedPreKey,
    initialRatchetPublic: bobSignedPreKeyPublic,
    initialPqRatchetKeyPair: bobPqPreKey
  });
  log("Triple Ratchet initialized — X25519 DH and ML-KEM-768 ratchets are ready.");
  setStep(3, "done");

  setStep(4);
  const firstFrame = await alice.encrypt(bytes("Hello Bob — this message is protected by the ratchet."));
  addMessage("Alice", "encrypted → decrypted by Bob", text(await bob.decrypt(firstFrame)));
  log("Alice → Bob: " + firstFrame.length.toLocaleString() + " byte opaque frame.");

  const replyFrame = await bob.encrypt(bytes("Hello Alice — Bob received it and ratcheted the session."));
  addMessage("Bob", "encrypted → decrypted by Alice", text(await alice.decrypt(replyFrame)));
  log("Bob → Alice: " + replyFrame.length.toLocaleString() + " byte opaque frame.");

  const f2 = await alice.encrypt(bytes("Message 2 — sent before message 3."));
  const f3 = await alice.encrypt(bytes("Message 3 — delivered first to exercise skipped-key handling."));
  addMessage("Alice", "out of order → Bob", text(await bob.decrypt(f3)));
  addMessage("Alice", "late delivery → Bob", text(await bob.decrypt(f2)));

  $("frame-size").textContent = firstFrame.length.toLocaleString() + " bytes";
  $("body-size").textContent = (firstFrame.length - 2353).toLocaleString() + " bytes";
  $("alice-status").textContent = "Session active"; $("bob-status").textContent = "Session active";
  log("Out-of-order delivery succeeded — Bob recovered the skipped message key.");
  log("Done. All cryptographic operations ran locally in this browser.");
  setStep(4, "done"); run.disabled = false;
}

function supportCheck() {
  const ok = globalThis.isSecureContext && globalThis.crypto?.subtle;
  if (ok) {
    $("support").textContent = "Secure browser context detected. Run the demo to test the required primitives.";
    run.disabled = false;
  } else {
    $("support").textContent = "This demo needs a secure context (HTTPS or localhost) with WebCrypto.";
  }
}
run.addEventListener("click", () => main().catch(error => {
  console.error(error); log("ERROR: " + error.message);
  $("alice-status").textContent = "Demo failed"; $("bob-status").textContent = "Demo failed";
  run.disabled = false;
}));
supportCheck();
