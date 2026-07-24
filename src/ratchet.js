// Triple Ratchet session with encrypted headers: per-message AES-256-GCM keys derived from a
// chain that rotates on every send/receive, a ratchet step whenever the peer's ratchet keys
// change, and the routing metadata itself (ratchet keys, counters) encrypted under a rotating
// header key -- so an observer of the wire frames sees only opaque ciphertext, never message
// cadence or ratchet timing, on top of the message content already being confidential. This
// follows Signal's own "Double Ratchet with header encryption" extension.
//
// The ratchet step itself runs TWO independent public-key ratchets in parallel and mixes both
// outputs into the root KDF, matching Signal's production "Triple Ratchet" (Double Ratchet +
// SPQR): a classical X25519 DH ratchet, and an ML-KEM-768 KEM ratchet that advances in lockstep
// with it. Where DH is symmetric (either side can compute the same value from their own private
// key and the peer's public key), a KEM is not -- only the keypair owner can decapsulate, so
// each ratchet step publishes a fresh ML-KEM public key (for the peer's NEXT step to encapsulate
// against) alongside a ciphertext (produced by encapsulating against the peer's most recently
// published key, for THEM to decapsulate). An adversary has to break both X25519 and ML-KEM to
// recover a step's chain key -- breaking either alone, now or with a future quantum computer,
// isn't enough. (Signal's production SPQR additionally chunks its ~1KB KEM payload across
// several messages via erasure coding purely to fit SMS-era bandwidth budgets -- that's a
// transport optimization, not a security requirement, so it's not reproduced here; the KEM
// public key and ciphertext just travel whole, inside the already-encrypted header.)
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
import { generatePqKeyPair, pqEncapsulate, pqDecapsulate } from "./pq.js";

const ROOT_INFO = bytes("webcrypto-ratchet-triple-ratchet-root-v3");
const HEADER_KEY_BOOTSTRAP_INFO = bytes("webcrypto-ratchet-header-key-init-v2");
const MESSAGE_LABEL = bytes("message:");
const CHAIN_LABEL = bytes("chain:");
const EMPTY_SALT = new Uint8Array(0);
const DEFAULT_MAX_SKIP = 1000;
const DEFAULT_AAD_PREFIX = "ratchet-msg";

async function kdfRootHE(rootKey, dhOutput, pqSharedSecret) {
  const material = await hkdf(concatBytes(dhOutput, pqSharedSecret), rootKey, ROOT_INFO, 96);
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
  if (typeof header.pqEk !== "string" || !header.pqEk) throw new Error("Invalid decrypted header: pqEk");
  if (typeof header.pqCt !== "string" || !header.pqCt) throw new Error("Invalid decrypted header: pqCt");
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
    // ML-KEM-768 ratchet, advancing in lockstep with the X25519 ratchet above (see file header).
    this.localPqRatchet = null;
    this.remotePqRatchetPublic = null;
    this.pqCtToSend = null;
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
   * Call after completing PQXDH as the handshake initiator.
   * @param {Uint8Array} sharedSecret - the PQXDH output
   * @param {Uint8Array} remoteRatchetPublic - peer's initial X25519 ratchet public key (their signed prekey)
   * @param {Uint8Array} remotePqRatchetPublic - peer's initial ML-KEM-768 ratchet public key (their PQ prekey)
   */
  async initAsInitiator(sharedSecret, remoteRatchetPublic, remotePqRatchetPublic) {
    const { sharedHka, sharedNhkb } = await bootstrapHeaderKeys(sharedSecret);
    this.rootKey = sharedSecret;
    this.remoteRatchetPublic = remoteRatchetPublic;
    this.remotePqRatchetPublic = remotePqRatchetPublic;
    this.localRatchet = await generateDhKeyPair();
    this.localRatchetPublic = await exportRawPublic(this.localRatchet.publicKey);
    this.localPqRatchet = generatePqKeyPair();
    const { cipherText: pqCt, sharedSecret: pqSharedSecret } = pqEncapsulate(this.remotePqRatchetPublic);
    this.pqCtToSend = pqCt;
    const next = await kdfRootHE(
      this.rootKey,
      await dh(this.localRatchet.privateKey, this.remoteRatchetPublic),
      pqSharedSecret
    );
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
   * Call after completing PQXDH as the handshake recipient.
   * @param {Uint8Array} sharedSecret - the PQXDH output
   * @param {object} params
   * @param {CryptoKeyPair} params.initialRatchetKeyPair - our already-published keypair (e.g. the
   *   signed prekey) that the initiator used as our stand-in X25519 ratchet key for their first message
   * @param {Uint8Array} params.initialRatchetPublic - raw public key matching initialRatchetKeyPair
   * @param {{publicKey: Uint8Array, secretKey: Uint8Array}} params.initialPqRatchetKeyPair - our
   *   already-published PQ prekey (from generatePqPreKeyPair) that the initiator encapsulated against
   * @param {Uint8Array|null} [params.remoteRatchetPublic] - initiator's X25519 ratchet public key, if
   *   already known from their handshake message; omit to defer until the first decrypt()
   * @param {Uint8Array|null} [params.remotePqRatchetPublic] - initiator's ML-KEM-768 ratchet public
   *   key, required whenever remoteRatchetPublic is given
   * @param {Uint8Array|null} [params.remotePqCipherText] - the ML-KEM ciphertext the initiator sent
   *   (encapsulated against initialPqRatchetKeyPair.publicKey), required whenever remoteRatchetPublic is given
   */
  async initAsRecipient(
    sharedSecret,
    {
      initialRatchetKeyPair,
      initialRatchetPublic,
      initialPqRatchetKeyPair,
      remoteRatchetPublic = null,
      remotePqRatchetPublic = null,
      remotePqCipherText = null,
    }
  ) {
    const { sharedHka, sharedNhkb } = await bootstrapHeaderKeys(sharedSecret);
    this.rootKey = sharedSecret;
    this.localRatchet = initialRatchetKeyPair;
    this.localRatchetPublic = initialRatchetPublic;
    this.localPqRatchet = initialPqRatchetKeyPair;
    this.headerKeySend = null;
    this.nextHeaderKeySend = sharedNhkb;
    this.headerKeyReceive = null;
    this.nextHeaderKeyReceive = sharedHka;
    if (!remoteRatchetPublic) return;
    // The initiator's ratchet keys are already known (BurnerRoom's signal-init includes them up
    // front), which is equivalent to a ratchet step having already conceptually fired -- so this
    // reuses the exact same advance the ratchet takes on every later step.
    await this._advance(remoteRatchetPublic, remotePqRatchetPublic, remotePqCipherText);
  }

  // Shared by decrypt()'s ratchet-detected branch and the eager branch of initAsRecipient above:
  // rotate the receive chain using the CURRENT local ratchet keys against the new remote keys,
  // promote the previously-established "next" header keys to "current" on both sides, then
  // generate fresh local ratchet keypairs and rotate the send chain. next* is always populated by
  // construction (from the bootstrap, or from a prior kdfRootHE call), so the promotion never
  // needs a null-guard -- matching Signal's own unconditional HKs=NHKs / HKr=NHKr swap.
  //
  // Runs the X25519 DH ratchet and the ML-KEM ratchet side by side, one step each, and mixes both
  // outputs into every kdfRootHE call. The KEM half is asymmetric where DH is symmetric: the
  // receive-side step decapsulates newIncomingPqCipherText (which the peer produced by
  // encapsulating against OUR current -- about to be retired -- localPqRatchet public key), while
  // the send-side step encapsulates against newRemotePqPublic (the fresh key the peer just
  // published) to produce the ciphertext THEY'll need to decapsulate next time we hear from them.
  async _advance(newRemotePublic, newRemotePqPublic, newIncomingPqCipherText) {
    this.previousSendCounter = this.sendCounter;
    this.sendCounter = 0;
    this.receiveCounter = 0;
    this.remoteRatchetPublic = newRemotePublic;
    this.remotePqRatchetPublic = newRemotePqPublic;

    this.headerKeyReceive = this.nextHeaderKeyReceive;
    const pqSharedSecretReceive = pqDecapsulate(newIncomingPqCipherText, this.localPqRatchet.secretKey);
    let next = await kdfRootHE(
      this.rootKey,
      await dh(this.localRatchet.privateKey, this.remoteRatchetPublic),
      pqSharedSecretReceive
    );
    this.rootKey = next.root;
    this.receiveChainKey = next.chain;
    this.nextHeaderKeyReceive = next.nextHeaderKey;

    this.localRatchet = await generateDhKeyPair();
    this.localRatchetPublic = await exportRawPublic(this.localRatchet.publicKey);
    this.localPqRatchet = generatePqKeyPair();
    const { cipherText: pqCtSend, sharedSecret: pqSharedSecretSend } = pqEncapsulate(this.remotePqRatchetPublic);
    this.pqCtToSend = pqCtSend;
    this.headerKeySend = this.nextHeaderKeySend;
    next = await kdfRootHE(
      this.rootKey,
      await dh(this.localRatchet.privateKey, this.remoteRatchetPublic),
      pqSharedSecretSend
    );
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

    const headerObj = {
      dh: uint8ToBase64(this.localRatchetPublic),
      pqEk: uint8ToBase64(this.localPqRatchet.publicKey),
      pqCt: uint8ToBase64(this.pqCtToSend),
      pn: this.previousSendCounter,
      n: counter,
    };
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

    // From here on the session state mutates (skipped-key consumption, chain advances, ratchet
    // steps) BEFORE the body's AES-GCM tag has been checked -- but a valid header only proves
    // knowledge of a header key, not that the body is authentic. An attacker who replays a
    // legitimate frame with a tampered body must not be able to burn the real message's key or
    // desync the ratchet. So: snapshot every piece of mutable state now, and roll all of it back
    // if anything past this point throws -- the Double Ratchet spec's "state is only updated if
    // decryption succeeds" requirement (DECRYPT's try/catch in the reference pseudocode). All
    // state transitions are reassignments (byte arrays and cache entries are never mutated in
    // place), so shallow captures -- including the shallow Map copy -- fully restore.
    const snapshot = this._captureState();
    try {
      // Whichever key matched, the specific counter may already sit in the skip cache -- this is
      // NOT the same question as "did the chain rotate": in an unrotated chain, the current header
      // key trivially matches every counter (past, present, or future), so a same-chain skipped
      // message must still be checked here rather than assumed "new" just because the current key
      // (not a stale one) is what happened to decrypt its header.
      const matchedHeaderKeyId = uint8ToBase64(matchedHeaderKey);
      const cached = this._takeSkippedKey(matchedHeaderKeyId, header.n);
      if (cached) return await this._decryptWith(frame, cached.messageKey, header.n);

      if (viaNext) {
        if (this.receiveChainKey) await this._skipReceiveKeys(header.pn);
        await this._advance(base64ToUint8(header.dh), base64ToUint8(header.pqEk), base64ToUint8(header.pqCt));
      } else if (header.n < this.receiveCounter) {
        throw new Error("Message key already used or unavailable");
      }

      if (header.n > this.receiveCounter) await this._skipReceiveKeys(header.n);

      const { messageKey, nextChain } = await kdfChain(this.receiveChainKey, this.receiveCounter);
      this.receiveChainKey = nextChain;
      this.receiveCounter += 1;
      return await this._decryptWith(frame, messageKey, header.n);
    } catch (error) {
      this._restoreState(snapshot);
      throw error;
    }
  }

  _captureState() {
    return {
      rootKey: this.rootKey,
      localRatchet: this.localRatchet,
      localRatchetPublic: this.localRatchetPublic,
      remoteRatchetPublic: this.remoteRatchetPublic,
      localPqRatchet: this.localPqRatchet,
      remotePqRatchetPublic: this.remotePqRatchetPublic,
      pqCtToSend: this.pqCtToSend,
      sendChainKey: this.sendChainKey,
      receiveChainKey: this.receiveChainKey,
      sendCounter: this.sendCounter,
      receiveCounter: this.receiveCounter,
      previousSendCounter: this.previousSendCounter,
      headerKeySend: this.headerKeySend,
      headerKeyReceive: this.headerKeyReceive,
      nextHeaderKeySend: this.nextHeaderKeySend,
      nextHeaderKeyReceive: this.nextHeaderKeyReceive,
      skippedKeys: new Map(this.skippedKeys),
    };
  }

  _restoreState(snapshot) {
    Object.assign(this, snapshot);
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
