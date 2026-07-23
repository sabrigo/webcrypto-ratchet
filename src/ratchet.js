// Double Ratchet session with encrypted headers: per-message AES-256-GCM keys derived from a
// chain that rotates on every send/receive, a DH ratchet step whenever the peer's ratchet
// public key changes, and the routing metadata itself (ratchet key, counters) encrypted under a
// rotating header key -- so an observer of the wire frames sees only opaque ciphertext, never
// message cadence or ratchet timing, on top of the message content already being confidential.
// This follows Signal's own "Double Ratchet with header encryption" extension.
//
// Includes a bounded skipped-message-key cache (the MAX_SKIP-capped MKSKIPPED store) so a
// dropped or reordered message doesn't kill the session -- only decrypting a message whose key
// is genuinely gone (already used, or older than the cache retains) fails. The cache also stores
// each entry's header key, so a message skipped two or more ratchet generations ago can still be
// recovered when it finally arrives (Signal's TrySkippedMessageKeysHE does the same).
import {
  dh,
  hmac,
  hkdf,
  bytes,
  text,
  concatBytes,
  uint8ToBase64,
  base64ToUint8,
  generateDhKeyPair,
  exportRawPublic,
} from "./primitives.js";

const ROOT_INFO = bytes("webcrypto-ratchet-double-ratchet-root-v2");
const HEADER_KEY_BOOTSTRAP_INFO = bytes("webcrypto-ratchet-header-key-init-v2");
const MESSAGE_LABEL = bytes("message:");
const CHAIN_LABEL = bytes("chain:");
const EMPTY_SALT = new Uint8Array(0);
const DEFAULT_MAX_SKIP = 1000;
const DEFAULT_AAD_PREFIX = "ratchet-msg";

async function kdfRootHE(rootKey, dhOutput) {
  const material = await hkdf(dhOutput, rootKey, ROOT_INFO, 96);
  return { root: material.slice(0, 32), chain: material.slice(32, 64), nextHeaderKey: material.slice(64, 96) };
}

async function kdfChain(chainKey, counter) {
  const counterBytes = bytes(String(counter));
  const messageKeyBytes = await hmac(chainKey, concatBytes(MESSAGE_LABEL, counterBytes));
  const nextChain = await hmac(chainKey, concatBytes(CHAIN_LABEL, counterBytes));
  const messageKey = await crypto.subtle.importKey("raw", messageKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return { messageKey, nextChain };
}

// Both parties independently derive the identical pair from the X3DH secret they already both
// hold -- no extra round trip needed. Which value becomes "current" vs "next" on each side is
// asymmetric (see initAsInitiator/initAsRecipient) -- that asymmetry, not the shared derivation
// itself, is what makes the very first message in each direction decryptable.
async function bootstrapHeaderKeys(sharedSecret) {
  const material = await hkdf(sharedSecret, EMPTY_SALT, HEADER_KEY_BOOTSTRAP_INFO, 64);
  return { sharedHka: material.slice(0, 32), sharedNhkb: material.slice(32, 64) };
}

async function encryptHeader(headerKeyBytes, headerObj) {
  const headerKey = await crypto.subtle.importKey("raw", headerKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const headerIv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: headerIv }, headerKey, bytes(JSON.stringify(headerObj)))
  );
  return { headerIv: uint8ToBase64(headerIv), header: uint8ToBase64(ciphertext) };
}

// Throws (via crypto.subtle.decrypt's GCM auth-tag check) if headerKeyBytes is the wrong key --
// callers rely on this to trial multiple candidate keys.
async function decryptHeader(headerKeyBytes, frame) {
  const headerKey = await crypto.subtle.importKey("raw", headerKeyBytes, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToUint8(frame.headerIv) },
    headerKey,
    base64ToUint8(frame.header)
  );
  return JSON.parse(text(plaintext));
}

function messageAdditionalData(prefix, counter, frame) {
  return concatBytes(bytes(`${prefix}:${counter}:`), base64ToUint8(frame.headerIv), base64ToUint8(frame.header));
}

function validateFrame(frame) {
  if (!frame || typeof frame !== "object") throw new Error("Invalid ratchet frame");
  if (typeof frame.headerIv !== "string" || !frame.headerIv) throw new Error("Invalid ratchet frame: headerIv");
  if (typeof frame.header !== "string" || !frame.header) throw new Error("Invalid ratchet frame: header");
  if (typeof frame.iv !== "string" || !frame.iv) throw new Error("Invalid ratchet frame: iv");
  if (typeof frame.body !== "string" || !frame.body) throw new Error("Invalid ratchet frame: body");
}

function validateDecryptedHeader(header) {
  if (!header || typeof header !== "object") throw new Error("Invalid decrypted header");
  if (typeof header.dh !== "string" || !header.dh) throw new Error("Invalid decrypted header: dh");
  if (!Number.isInteger(header.n) || header.n < 0) throw new Error("Invalid decrypted header: n");
  if (!Number.isInteger(header.pn) || header.pn < 0) throw new Error("Invalid decrypted header: pn");
}

export class DoubleRatchetSession {
  /**
   * @param {object} [options]
   * @param {number} [options.maxSkip] - cap on how many message keys can be skipped/cached at
   *   once, both per-jump and in total (default 1000, matching Signal's own reference value).
   *   Guards against a malicious/corrupt counter forcing unbounded memory growth.
   * @param {string} [options.associatedDataPrefix] - domain-separation string mixed into the
   *   AES-GCM additional authenticated data alongside the counter and the header ciphertext.
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
    this.headerKeySend = null;
    this.headerKeyReceive = null;
    this.nextHeaderKeySend = null;
    this.nextHeaderKeyReceive = null;
    // `${headerKeyIdBase64}:${counter}` -> { headerKey, messageKey } -- storing the header key
    // inline per entry (rather than a separate id->key table) since maxSkip already bounds the
    // total count, so there's no real table to dedupe.
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
    const { sharedHka, sharedNhkb } = await bootstrapHeaderKeys(sharedSecret);
    this.rootKey = sharedSecret;
    this.remoteRatchetPublic = remoteRatchetPublic;
    this.localRatchet = await generateDhKeyPair();
    this.localRatchetPublic = await exportRawPublic(this.localRatchet.publicKey);
    const next = await kdfRootHE(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.sendChainKey = next.chain;
    this.nextHeaderKeySend = next.nextHeaderKey;
    // Only the initiator has a usable "current" key on either side at t=0 -- Bob's first reply
    // will only decrypt under nextHeaderKeyReceive, never a "current" headerKeyReceive, because
    // he hasn't ratcheted anything of his own yet either.
    this.headerKeySend = sharedHka;
    this.headerKeyReceive = null;
    this.nextHeaderKeyReceive = sharedNhkb;
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
    const { sharedHka, sharedNhkb } = await bootstrapHeaderKeys(sharedSecret);
    this.rootKey = sharedSecret;
    this.localRatchet = initialRatchetKeyPair;
    this.localRatchetPublic = initialRatchetPublic;
    this.headerKeySend = null;
    this.nextHeaderKeySend = sharedNhkb;
    this.headerKeyReceive = null;
    this.nextHeaderKeyReceive = sharedHka;
    if (!remoteRatchetPublic) return;
    // The initiator's ratchet key is already known (BurnerRoom's signal-init includes it up
    // front), which is equivalent to a DH ratchet having already conceptually fired -- so this
    // reuses the exact same advance the ratchet takes on every later step.
    await this._advance(remoteRatchetPublic);
  }

  // Shared by _dhRatchet-on-receive and the eager branch of initAsRecipient above: rotate the
  // receive chain using the CURRENT local ratchet key against the new remote key, promote the
  // previously-established "next" header keys to "current" on both sides, then generate a fresh
  // local ratchet keypair and rotate the send chain. next* is always populated by construction
  // (from the bootstrap, or from a prior kdfRootHE call), so the promotion never needs a
  // null-guard -- matching Signal's own unconditional HKs=NHKs / HKr=NHKr swap.
  async _advance(newRemotePublic) {
    this.previousSendCounter = this.sendCounter;
    this.sendCounter = 0;
    this.receiveCounter = 0;
    this.remoteRatchetPublic = newRemotePublic;

    this.headerKeyReceive = this.nextHeaderKeyReceive;
    let next = await kdfRootHE(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.receiveChainKey = next.chain;
    this.nextHeaderKeyReceive = next.nextHeaderKey;

    this.localRatchet = await generateDhKeyPair();
    this.localRatchetPublic = await exportRawPublic(this.localRatchet.publicKey);
    this.headerKeySend = this.nextHeaderKeySend;
    next = await kdfRootHE(this.rootKey, await dh(this.localRatchet.privateKey, this.remoteRatchetPublic));
    this.rootKey = next.root;
    this.sendChainKey = next.chain;
    this.nextHeaderKeySend = next.nextHeaderKey;
  }

  // Derives and caches every not-yet-used message key on the CURRENT receive chain from
  // receiveCounter up to (but not including) untilCounter, tagged with the header key active for
  // that chain right now. Called both when skipping ahead within a chain, and to drain a chain's
  // remaining keys just before _advance() retires it.
  async _skipReceiveKeys(untilCounter) {
    if (!this.receiveChainKey) return;
    if (untilCounter - this.receiveCounter > this.maxSkip) {
      throw new Error("Too many skipped messages");
    }
    const headerKey = this.headerKeyReceive;
    const headerKeyId = uint8ToBase64(headerKey);
    while (this.receiveCounter < untilCounter) {
      const { messageKey, nextChain } = await kdfChain(this.receiveChainKey, this.receiveCounter);
      this._cacheSkippedKey(headerKeyId, headerKey, this.receiveCounter, messageKey);
      this.receiveChainKey = nextChain;
      this.receiveCounter += 1;
    }
  }

  _cacheSkippedKey(headerKeyId, headerKey, counter, messageKey) {
    this.skippedKeys.set(`${headerKeyId}:${counter}`, { headerKey, messageKey });
    while (this.skippedKeys.size > this.maxSkip) {
      this.skippedKeys.delete(this.skippedKeys.keys().next().value);
    }
  }

  _takeSkippedKey(headerKeyId, counter) {
    const key = `${headerKeyId}:${counter}`;
    const entry = this.skippedKeys.get(key);
    if (entry) this.skippedKeys.delete(key);
    return entry || null;
  }

  /** Encrypts plaintext bytes into a frame ready to send: {headerIv, header, iv, body}, all base64. */
  async encrypt(plaintextBytes) {
    if (!this.sendChainKey) throw new Error("Ratchet session not ready to send");
    const counter = this.sendCounter++;
    const { messageKey, nextChain } = await kdfChain(this.sendChainKey, counter);
    this.sendChainKey = nextChain;

    const headerObj = { dh: uint8ToBase64(this.localRatchetPublic), pn: this.previousSendCounter, n: counter };
    const { headerIv, header } = await encryptHeader(this.headerKeySend, headerObj);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const frameForAad = { headerIv, header };
    const additionalData = messageAdditionalData(this.associatedDataPrefix, counter, frameForAad);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, messageKey, plaintextBytes)
    );

    return { headerIv, header, iv: uint8ToBase64(iv), body: uint8ToBase64(ciphertext) };
  }

  /**
   * Decrypts a frame produced by encrypt(). Tries the header ciphertext against the current
   * receive header key, then the "next" one (a ratchet just happened), then every header key
   * still referenced by an unconsumed skipped-key cache entry (a message skipped two or more
   * ratchet generations ago, arriving very late) -- matching Signal's TrySkippedMessageKeysHE.
   * Whichever succeeds reveals {dh, pn, n}, and the same in-order/out-of-order/ratchet decision
   * logic as before runs from there, just fed the now-decrypted header instead of what used to
   * be plaintext wire fields.
   */
  async decrypt(frame) {
    validateFrame(frame);

    let header = null;
    let matchedHeaderKey = null;
    let viaNext = false;

    if (this.headerKeyReceive) {
      try {
        header = await decryptHeader(this.headerKeyReceive, frame);
        matchedHeaderKey = this.headerKeyReceive;
      } catch {}
    }
    if (!header && this.nextHeaderKeyReceive) {
      try {
        header = await decryptHeader(this.nextHeaderKeyReceive, frame);
        matchedHeaderKey = this.nextHeaderKeyReceive;
        viaNext = true;
      } catch {}
    }
    if (!header) {
      const tried = new Set();
      for (const entry of this.skippedKeys.values()) {
        const id = uint8ToBase64(entry.headerKey);
        if (tried.has(id)) continue;
        tried.add(id);
        try {
          header = await decryptHeader(entry.headerKey, frame);
          matchedHeaderKey = entry.headerKey;
          break;
        } catch {}
      }
    }
    if (!header) throw new Error("Unable to decrypt message header");
    validateDecryptedHeader(header);

    // Whichever key matched, the specific counter may already sit in the skip cache -- this is
    // NOT the same question as "did the chain rotate": in an unrotated chain, the current header
    // key trivially matches every counter (past, present, or future), so a same-chain skipped
    // message must still be checked here rather than assumed "new" just because the current key
    // (not a stale one) is what happened to decrypt its header.
    const matchedHeaderKeyId = uint8ToBase64(matchedHeaderKey);
    const cached = this._takeSkippedKey(matchedHeaderKeyId, header.n);
    if (cached) return this._decryptWith(frame, cached.messageKey, header.n);

    if (viaNext) {
      if (this.receiveChainKey) await this._skipReceiveKeys(header.pn);
      await this._advance(base64ToUint8(header.dh));
    } else if (header.n < this.receiveCounter) {
      throw new Error("Message key already used or unavailable");
    }

    if (header.n > this.receiveCounter) await this._skipReceiveKeys(header.n);

    const { messageKey, nextChain } = await kdfChain(this.receiveChainKey, this.receiveCounter);
    this.receiveChainKey = nextChain;
    this.receiveCounter += 1;
    return this._decryptWith(frame, messageKey, header.n);
  }

  async _decryptWith(frame, messageKey, counter) {
    const additionalData = messageAdditionalData(this.associatedDataPrefix, counter, frame);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToUint8(frame.iv), additionalData },
      messageKey,
      base64ToUint8(frame.body)
    );
    return new Uint8Array(plaintext);
  }
}
