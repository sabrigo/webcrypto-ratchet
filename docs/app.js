import {
  generateDhKeyPair, generateSigningKeyPair, generatePqPreKeyPair,
  exportRawPublic, signBytes, deriveSecretAsInitiator, deriveSecretAsRecipient,
  DoubleRatchetSession, bytes, text
} from "https://esm.sh/webcrypto-ratchet@0.7.2?bundle";

const $ = id => document.getElementById(id);
const run = $("run"), logEl = $("log"), messagesEl = $("messages");

let aliceSession = null;
let bobSession = null;
let sessionReady = false;

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
  return Array.from(value.slice(0, length))
    .map(x => x.toString(16).padStart(2, "0"))
    .join("") + "…";
}

function setStats(id, values) {
  $(id).innerHTML = values
    .map(([k, v]) => "<dt>" + k + "</dt><dd>" + v + "</dd>")
    .join("");
}

function addMessage(who, direction, content, frameLength = null) {
  const empty = messagesEl.querySelector(".empty");
  if (empty) empty.remove();

  const div = document.createElement("div");
  div.className = "message " + (who === "Alice" ? "alice-msg" : "bob-msg");

  const label = document.createElement("small");
  label.textContent = who + " · " + direction;

  const body = document.createElement("div");
  body.textContent = content;

  if (frameLength !== null) {
    const meta = document.createElement("em");
    meta.textContent = `${frameLength.toLocaleString()} byte encrypted frame`;
    div.append(label, body, meta);
  } else {
    div.append(label, body);
  }

  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function setMessagingEnabled(enabled) {
  sessionReady = enabled;
  $("alice-input").disabled = !enabled;
  $("alice-send").disabled = !enabled;
  $("bob-input").disabled = !enabled;
  $("bob-send").disabled = !enabled;
}

function toBase64(data) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < data.length; i += chunkSize) {
    binary += String.fromCharCode(...data.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function toHex(data, maxBytes = 256) {
  const slice = data.subarray(0, Math.min(maxBytes, data.length));
  let output = "";
  for (let i = 0; i < slice.length; i += 16) {
    const row = slice.subarray(i, i + 16);
    const hex = Array.from(row, b => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(row, b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".").join("");
    output += i.toString(16).padStart(4, "0") + "  " + hex.padEnd(47, " ") + "  " + ascii + "\n";
  }
  return output.trimEnd();
}

function showCiphertext(from, frame, plaintextLength) {
  const base64 = toBase64(frame);
  $("cipher-summary").textContent =
    `${from} produced a ${frame.length.toLocaleString()} byte opaque frame for a ${plaintextLength.toLocaleString()} byte plaintext.`;
  $("cipher-base64").textContent = base64;
  $("cipher-hex").textContent = toHex(frame);
  $("toggle-cipher").disabled = false;
  $("toggle-cipher").textContent = "Show raw frame";
  $("cipher-content").hidden = true;
}

async function sendMessage(from, message) {
  const value = message.trim();
  if (!sessionReady || !value) return;

  const sender = from === "Alice" ? aliceSession : bobSession;
  const receiver = from === "Alice" ? bobSession : aliceSession;
  const input = from === "Alice" ? $("alice-input") : $("bob-input");

  try {
    const plaintextBytes = bytes(value);
    const frame = await sender.encrypt(plaintextBytes);
    const decrypted = text(await receiver.decrypt(frame));
    showCiphertext(from, frame, plaintextBytes.length);

    addMessage(
      from,
      `encrypted → decrypted by ${from === "Alice" ? "Bob" : "Alice"}`,
      decrypted,
      frame.length
    );

    $("frame-size").textContent = `${frame.length.toLocaleString()} bytes`;
    $("body-size").textContent = Math.max(0, frame.length - 2353).toLocaleString() + " bytes";

    log(`${from} → ${from === "Alice" ? "Bob" : "Alice"}: ${frame.length.toLocaleString()} byte opaque frame.`);
    input.value = "";
    input.focus();
  } catch (error) {
    log("ERROR sending message: " + error.message);
  }
}

async function main() {
  run.disabled = true;
  setMessagingEnabled(false);
  logEl.textContent = "";
  messagesEl.innerHTML = '<div class="empty">Establishing the encrypted session…</div>';
  $("cipher-summary").textContent = "Send a message to inspect its encrypted frame.";
  $("cipher-base64").textContent = "";
  $("cipher-hex").textContent = "";
  $("toggle-cipher").disabled = true;
  $("cipher-content").hidden = true;

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

  setStats("alice-stats", [
    ["Identity", "X25519"],
    ["Signing", "Ed25519"],
    ["Ratchet", "X25519 + ML-KEM-768"],
    ["Header", "AES-256-GCM"],
    ["Message KDF", "HMAC-SHA256"]
  ]);
  setStats("bob-stats", [
    ["Identity", "X25519"],
    ["Signing", "Ed25519"],
    ["Ratchet", "X25519 + ML-KEM-768"],
    ["Header", "AES-256-GCM"],
    ["Message KDF", "HMAC-SHA256"]
  ]);

  $("alice-status").textContent = "Keys ready";
  $("bob-status").textContent = "Prekeys published";
  setStep(1, "done");

  setStep(2);
  log("Bob published a signed X25519 prekey + signed ML-KEM-768 prekey.");

  const { secret: aliceSecret, pqCipherText } = await deriveSecretAsInitiator({
    identityPrivateKey: aliceIdentity.privateKey,
    identityPublicKeyRaw: aliceIdentityPublic,
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
    identityPrivateKey: bobIdentity.privateKey,
    identityPublicKeyRaw: bobIdentityPublic,
    signedPreKeyPrivateKey: bobSignedPreKey.privateKey,
    peerIdentityPublicKeyRaw: aliceIdentityPublic,
    peerEphemeralPublicKeyRaw: aliceEphemeralPublic,
    pqPreKeySecretKey: bobPqPreKey.secretKey,
    pqCipherText,
    contextInfo: "browser-demo"
  });

  const secretsMatch = aliceSecret.length === bobSecret.length &&
    aliceSecret.every((v, i) => v === bobSecret[i]);

  if (!secretsMatch) throw new Error("PQXDH shared secrets did not match.");

  log("PQXDH complete — both sides derived the same 32-byte root secret (" + hexPreview(aliceSecret) + ").");
  setStep(2, "done");

  setStep(3);

  aliceSession = new DoubleRatchetSession({ associatedDataPrefix: "browser-demo" });
  bobSession = new DoubleRatchetSession({ associatedDataPrefix: "browser-demo" });

  await aliceSession.initAsInitiator(
    aliceSecret,
    bobSignedPreKeyPublic,
    bobPqPreKey.publicKey
  );

  await bobSession.initAsRecipient(bobSecret, {
    initialRatchetKeyPair: bobSignedPreKey,
    initialRatchetPublic: bobSignedPreKeyPublic,
    initialPqRatchetKeyPair: bobPqPreKey
  });

  log("Triple Ratchet initialized — X25519 DH and ML-KEM-768 ratchets are ready.");
  setStep(3, "done");

  setStep(4);
  setStep(4, "done");

  $("alice-status").textContent = "Session active";
  $("bob-status").textContent = "Session active";
  messagesEl.innerHTML = '<div class="empty">Session ready. Type a message above to send it through the ratchet.</div>';

  setMessagingEnabled(true);
  $("alice-input").focus();

  log("Encrypted messaging is ready.");
  log("Every message below creates a fresh opaque ciphertext frame.");
  log("All cryptographic operations run locally in this browser.");
  run.disabled = false;
}

$("alice-form").addEventListener("submit", event => {
  event.preventDefault();
  sendMessage("Alice", $("alice-input").value);
});

$("bob-form").addEventListener("submit", event => {
  event.preventDefault();
  sendMessage("Bob", $("bob-input").value);
});

$("toggle-cipher").addEventListener("click", () => {
  const content = $("cipher-content");
  const isHidden = content.hidden;
  content.hidden = !isHidden;
  $("toggle-cipher").textContent = isHidden ? "Hide raw frame" : "Show raw frame";
});

async function supportCheck() {
  const ok = globalThis.isSecureContext && globalThis.crypto?.subtle;

  if (ok) {
    $("support").textContent =
      "Secure browser context detected. Run the demo to establish the session.";
    run.disabled = false;
  } else {
    $("support").textContent =
      "This demo needs a secure context (HTTPS or localhost) with WebCrypto.";
  }
}

run.addEventListener("click", () => main().catch(error => {
  console.error(error);
  log("ERROR: " + error.message);
  $("alice-status").textContent = "Demo failed";
  $("bob-status").textContent = "Demo failed";
  setMessagingEnabled(false);
  run.disabled = false;
}));

supportCheck();
