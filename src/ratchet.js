// Double Ratchet session: per-message AES-256-GCM keys derived from a chain that rotates on
// every send/receive, plus a DH ratchet step whenever the peer's ratchet public key changes.
// Includes a bounded skipped-message-key cache (the MAX_SKIP-capped MKSKIPPED store from the
// Signal spec) so a dropped or reordered message doesn't kill the session -- only decrypting
// a message whose key is genuinely gone (already used, or older than the cache retains) fails.
import { dh, hmac, hkdf, bytes, concatBytes, equalBytes, uint8ToBase64, base64ToUint8, generateDhKeyPair, exportRawPublic } from "./primitives.js";

const ROOT_INFO = bytes("webcrypto-ratchet-double-ratchet-root-v1");
const MESSAGE_LABEL = bytes("message:");
const CHAIN_LABEL = bytes("chain:");
const DEFAULT_MAX_SKIP = 1000;
const DEFAULT_AAD_PREFIX = "ratchet-msg";

async function kdfRoot(rootKey, dhOutput) {
  const material = await hkdf(dhOutput, rootKey, ROOT_INFO, 64);
  return { root: material.slice(0, 32), chain: material.slice(32, 64) };
}

async function kdfChain(chainKey, counter) {
  const counterBytes = bytes(String(counter));
  const messageKeyBytes = await hmac(chainKey, concatBytes(MESSAGE_LABEL, counterBytes));
  const nextChain = await hmac(chainKey, concatBytes(CHAIN_LABEL, counterBytes));
  const messageKey = await crypto.subtle.importKey("raw", messageKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return { messageKey, nextChain };
}

function validateFrame(frame) {
  if (!frame || typeof frame !== "object") throw new Error("Invalid ratchet frame");
  if (typeof frame.dh !== "string" || !frame.dh) throw new Error("Invalid ratchet frame: dh");
  if (!Number.isInteger(frame.n) || frame.n < 0) throw new Error("Invalid ratchet frame: n");
  if (!Number.isInteger(frame.pn) || frame.pn < 0) throw new Error("Invalid ratchet frame: pn");
  if (typeof frame.iv !== "string" || !frame.iv) throw new Error("Invalid ratchet frame: iv");
  if (typeof frame.body !== "string" || !frame.body) throw new Error("Invalid ratchet frame: body");
}

export class DoubleRatchetSession {
  /**
   * @param {object} [options]
   * @param {number} [options.maxSkip] - cap on how many message keys can be skipped/cached at
   *   once, both per-jump and in total (default 1000, matching Signal's own reference value).
   *   Guards against a malicious/corrupt counter forcing unbounded memory growth.
   * @param {string} [options.associatedDataPrefix] - domain-separation string mixed into the
   *   AES-GCM additional authenticated data alongside the counter and ratchet key.
   */
  constructor({ maxSkip = DEFAULT_MAX_SKIP, associatedDataPrefix = DEFAULT_AAD_PREFIX } = {}) {
    this.maxSkip = maxSkip;
    this.associatedDataPrefix = associatedDataPrefix;
    this.rootKey = null;
    this.localRatchet = null;
    this.localRatchetPublic = null;
    this.remoteRatchetPublic = null;
    this.sendChainKey = null;
    this.receiveChainKey = null;
    this.sendCounter = 0;
    this.receiveCounter = 0;
    this.previousSendCounter = 0;
    this.skippedKeys = new Map();
  }

  get canSend() {
    return !!this.sendChainKey;
  }

  /**
   * Call after completing X3DH as the handshake initiator.
   * @param {Uint8Array} sharedSecret - the X3DH output
   * @param {Uint8Array} remoteRatchetPublic - peer's initial ratchet public key (their signed prekey)
   */
  async initAsInitiator(sharedSecret, remoteRatchetPublic) {
    this.rootKey = sharedSecret;
    this.remoteRatchetPublic = remoteRatchetPublic;
    this.localRatchet = await generateDhKeyPair();
    this.localRatchetPublic = await exportRawPublic(this.localRatchet.publicKey);
    const next = await kdfRoot(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.sendChainKey = next.chain;
  }

  /**
   * Call after completing X3DH as the handshake recipient.
   * @param {Uint8Array} sharedSecret - the X3DH output
   * @param {object} params
   * @param {CryptoKeyPair} params.initialRatchetKeyPair - our already-published keypair (e.g. the
   *   signed prekey) that the initiator used as our stand-in ratchet key for their first message
   * @param {Uint8Array} params.initialRatchetPublic - raw public key matching initialRatchetKeyPair
   * @param {Uint8Array|null} [params.remoteRatchetPublic] - initiator's ratchet public key, if
   *   already known from their handshake message; omit to defer until the first decrypt()
   */
  async initAsRecipient(sharedSecret, { initialRatchetKeyPair, initialRatchetPublic, remoteRatchetPublic = null }) {
    this.rootKey = sharedSecret;
    this.localRatchet = initialRatchetKeyPair;
    this.localRatchetPublic = initialRatchetPublic;
    if (!remoteRatchetPublic) return;

    this.remoteRatchetPublic = remoteRatchetPublic;
    let next = await kdfRoot(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.receiveChainKey = next.chain;

    this.localRatchet = await generateDhKeyPair();
    this.localRatchetPublic = await exportRawPublic(this.localRatchet.publicKey);
    next = await kdfRoot(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.sendChainKey = next.chain;
  }

  async _dhRatchet(newRemotePublic) {
    this.previousSendCounter = this.sendCounter;
    this.sendCounter = 0;
    this.receiveCounter = 0;
    this.remoteRatchetPublic = newRemotePublic;

    let next = await kdfRoot(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.receiveChainKey = next.chain;

    this.localRatchet = await generateDhKeyPair();
    this.localRatchetPublic = await exportRawPublic(this.localRatchet.publicKey);
    next = await kdfRoot(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.sendChainKey = next.chain;
  }

  // Derives and caches every not-yet-used message key on the CURRENT receive chain from
  // receiveCounter up to (but not including) untilCounter. Called both when skipping ahead
  // within a chain, and to drain a chain's remaining keys just before a DH ratchet retires it.
  async _skipReceiveKeys(untilCounter) {
    if (!this.receiveChainKey) return;
    if (untilCounter - this.receiveCounter > this.maxSkip) {
      throw new Error("Too many skipped messages");
    }
    const ratchetTag = uint8ToBase64(this.remoteRatchetPublic);
    while (this.receiveCounter < untilCounter) {
      const { messageKey, nextChain } = await kdfChain(this.receiveChainKey, this.receiveCounter);
      this._cacheSkippedKey(ratchetTag, this.receiveCounter, messageKey);
      this.receiveChainKey = nextChain;
      this.receiveCounter += 1;
    }
  }

  _cacheSkippedKey(ratchetTag, counter, messageKey) {
    this.skippedKeys.set(`${ratchetTag}:${counter}`, messageKey);
    while (this.skippedKeys.size > this.maxSkip) {
      this.skippedKeys.delete(this.skippedKeys.keys().next().value);
    }
  }

  _takeSkippedKey(ratchetTag, counter) {
    const key = `${ratchetTag}:${counter}`;
    const messageKey = this.skippedKeys.get(key);
    if (messageKey) this.skippedKeys.delete(key);
    return messageKey || null;
  }

  /** Encrypts plaintext bytes into a frame ready to send: {dh, pn, n, iv, body}, all base64/number. */
  async encrypt(plaintextBytes) {
    if (!this.sendChainKey) throw new Error("Ratchet session not ready to send");
    const counter = this.sendCounter++;
    const { messageKey, nextChain } = await kdfChain(this.sendChainKey, counter);
    this.sendChainKey = nextChain;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ratchetPublicB64 = uint8ToBase64(this.localRatchetPublic);
    const additionalData = bytes(`${this.associatedDataPrefix}:${counter}:${ratchetPublicB64}`);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, messageKey, plaintextBytes)
    );

    return {
      dh: ratchetPublicB64,
      pn: this.previousSendCounter,
      n: counter,
      iv: uint8ToBase64(iv),
      body: uint8ToBase64(ciphertext),
    };
  }

  /**
   * Decrypts a frame produced by encrypt(). Handles in-order, out-of-order (via the skipped-key
   * cache), and DH-ratchet transitions -- including a message that arrives late from a chain
   * that's already been superseded by a newer one, which is checked against the cache by the
   * frame's own ratchet key first so it can never trigger ratcheting backward.
   */
  async decrypt(frame) {
    validateFrame(frame);
    const remotePublic = base64ToUint8(frame.dh);

    const cachedKey = this._takeSkippedKey(frame.dh, frame.n);
    if (cachedKey) return this._decryptWith(frame, cachedKey);

    const ratchetChanged = !equalBytes(this.remoteRatchetPublic, remotePublic);
    if (ratchetChanged) {
      if (this.receiveChainKey) await this._skipReceiveKeys(frame.pn);
      await this._dhRatchet(remotePublic);
    } else if (frame.n < this.receiveCounter) {
      throw new Error("Message key already used or unavailable");
    }

    if (frame.n > this.receiveCounter) await this._skipReceiveKeys(frame.n);

    const { messageKey, nextChain } = await kdfChain(this.receiveChainKey, this.receiveCounter);
    this.receiveChainKey = nextChain;
    this.receiveCounter += 1;
    return this._decryptWith(frame, messageKey);
  }

  async _decryptWith(frame, messageKey) {
    const additionalData = bytes(`${this.associatedDataPrefix}:${frame.n}:${frame.dh}`);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToUint8(frame.iv), additionalData },
      messageKey,
      base64ToUint8(frame.body)
    );
    return new Uint8Array(plaintext);
  }
}
