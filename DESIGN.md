# webcrypto-ratchet: design note

Describes the protocol as implemented in v0.7.3 (`src/x3dh.js`, `src/ratchet.js`). Written for
reviewers: it states the key schedule and state machine, then lists every place the design
departs from Signal's published specifications, then the points I am least sure about.

**Status: unaudited. No security proof. Not wire-compatible with Signal.**

## 1. Primitives

| Role | Primitive | Source |
|---|---|---|
| DH | X25519 | WebCrypto |
| Signatures (prekeys only) | Ed25519 | WebCrypto |
| KEM | ML-KEM-768 (FIPS 203) | `@noble/post-quantum` 0.7.x |
| KDF | HKDF-SHA256, HMAC-SHA256 | WebCrypto |
| AEAD | AES-256-GCM, random 96-bit IV | WebCrypto |

Notation: `HKDF(ikm, salt, info, len)`; `‖` is concatenation; all DH outputs and KEM shared
secrets are 32 bytes; `Encaps(pk) -> (ct, ss)`.

## 2. Handshake (PQXDH-style)

Each party holds: X25519 identity key `IK`, a **separate** Ed25519 signing key `SigK`, X25519
signed prekey `SPK`, ML-KEM signed prekey `PQSPK`, optional X25519 one-time prekeys `OPK`.
Bob publishes `IK_B, SigK_B, SPK_B, Sig(SigK_B, SPK_B), PQSPK_B, Sig(SigK_B, PQSPK_B), [OPK_B]`.
Signatures are over the raw public-key bytes.

Alice verifies both signatures, generates ephemeral `EK_A`, and computes:

```
DH1 = DH(IK_A, SPK_B)      DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)      DH4 = DH(EK_A, OPK_B)   (empty string if no OPK)
(ct0, ss0) = Encaps(PQSPK_B)

SK = HKDF(ikm  = DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss0,
          salt = SHA-256("pqxdh-v2:" ‖ contextInfo),
          info = "webcrypto-ratchet-pqxdh-root-v2" ‖ IK_A ‖ IK_B,
          len  = 32)
```

`contextInfo` is an application-supplied string. Alice sends `IK_A, EK_A, ct0` and prekey
identifiers; the library does not define that message. Bob recomputes `SK`.

## 3. Ratchet

### 3.1 Initialisation

```
HK_a ‖ NHK_b = HKDF(ikm = SK, salt = "", info = "webcrypto-ratchet-header-key-init-v2", 64)
RK_0 = SK
```

`SPK_B` is Bob's initial DH ratchet key and `PQSPK_B` is his initial KEM ratchet key. Alice
generates `(a_1, A_1)` (X25519) and `(dk_A1, ek_A1)` (ML-KEM), encapsulates a **second** time
against `PQSPK_B` to get `(ct_1, ss_1)`, and performs one root step (3.2) with
`DH(a_1, SPK_B)` and `ss_1` to obtain her first sending chain. Her sending header key is `HK_a`;
her next receiving header key is `NHK_b`.

### 3.2 Root step

```
RK' ‖ CK ‖ NHK = HKDF(ikm  = DH_out ‖ ss,
                      salt = RK,
                      info = "webcrypto-ratchet-triple-ratchet-root-v3",
                      len  = 96)
```

A full ratchet turn, run when a header arrives carrying new remote keys `(R, ek_R, ct_R)`:

1. Receive step: `DH_out = DH(local_dh, R)`, `ss = Decaps(local_dk, ct_R)` → receiving chain,
   next receiving header key.
2. Generate fresh local X25519 and ML-KEM keypairs. `(ct, ss) = Encaps(ek_R)`.
3. Send step: `DH_out = DH(new_local_dh, R)`, `ss` from step 2 → sending chain, next sending
   header key.

So the KEM ratchet advances in lockstep with the DH ratchet: every root step has exactly one DH
output and one KEM secret as input. Each ML-KEM keypair receives one encapsulation, except
`PQSPK_B`, which receives two per session (`ss0`, `ss1`) and is shared across sessions.

### 3.3 Symmetric chain

```
MK_n     = HMAC(CK_n, "message:" ‖ decimal(n))     (AES-256-GCM key, used once)
CK_{n+1} = HMAC(CK_n, "chain:"   ‖ decimal(n))
```

### 3.4 Frame

```
header = version(1) ‖ dh_pub(32) ‖ pq_ek(1184) ‖ pq_ct(1088) ‖ pn(4) ‖ n(4)        (2313 bytes)
frame  = hIV(12) ‖ AES-GCM(HK, hIV, header) ‖ bIV(12) ‖ AES-GCM(MK_n, bIV, plaintext, aad)
aad    = prefix ‖ ":" ‖ decimal(n) ‖ ":" ‖ hIV ‖ header_ciphertext
```

Every frame carries the full ML-KEM encapsulation key and ciphertext for the current epoch, so
all frames have the same overhead (2,369 bytes) whether or not they trigger a ratchet step.

### 3.5 Receiving

Trial-decrypt the header with: current `HK_r`, then `NHK_r` (implies a ratchet turn), then each
distinct header key held in the skipped-key store. Skipped message keys are stored with their
header key, capped at `maxSkip` (default 1000) both per jump and in total, evicted FIFO, with no
time-based expiry. All state changes made while processing a frame are rolled back unless the
body's GCM tag verifies. `encrypt`/`decrypt` calls on a session are serialised.

## 4. Deviations from Signal's specifications

| # | Signal | Here |
|---|---|---|
| D1 | Triple Ratchet runs the Double Ratchet and SPQR as two independent ratchets and combines their **output keys** with a KDF. The DH root chain is unchanged. | The KEM secret is mixed into the **DH root KDF** at every DH ratchet step. There is no separate PQ ratchet and no SPQR. This library calls the result a "Hybrid Double Ratchet"; it is not Signal's Triple Ratchet. (The HKDF `info` label still contains `triple-ratchet` for compatibility with existing sessions.) |
| D2 | SPQR epochs advance on their own schedule; KEM material is chunked across messages with erasure coding. | KEM epoch = DH epoch. Full `ek` and `ct` in every frame. |
| D3 | PQXDH: `SK = KDF(0xFF*32 ‖ DH1..4 ‖ SS)`, zero salt, protocol-name info. | Section 2. No `0xFF` prefix; salt is a hash of an application string; info carries both identity keys. |
| D4 | One identity key, signs prekeys via XEdDSA. Signed bytes are a typed encoding of the key. | Separate Ed25519 signing key, **not bound** to `IK` by the library and not an input to the KDF. Signatures are over raw key bytes with no type or context label. |
| D5 | `AD = Encode(IK_A) ‖ Encode(IK_B)` is passed to the ratchet as AEAD associated data. PQXDH rev. 3 discusses binding `PQPK` as well. | Identity keys are bound in the handshake KDF `info` only. `SPK_B`, `PQSPK_B`, `OPK_B`, `EK_A`, `ct0` are **not** bound by a transcript hash; binding relies on the DH outputs and on ML-KEM deriving `ss` from `H(ek)`. |
| D6 | One-time PQ prekeys, with a last-resort signed PQ prekey as fallback. | Only the signed PQ prekey. Without an X25519 OPK the handshake is replayable. |
| D7 | Header-encryption variant: `SK`, `HK_a`, `NHK_b` are separate outputs of the handshake. | `HK_a`, `NHK_b` are derived from `SK`, and `SK` is also used directly as `RK_0`. `SK` therefore appears once as HKDF IKM (empty salt) and once as HKDF salt. |
| D8 | `KDF_CK` uses constant inputs (`0x01`, `0x02`). | Inputs include the message counter. |
| D9 | AEAD is AES-CBC + HMAC with derived IV (libsignal). | AES-256-GCM with random IVs. Header keys are reused across a sending epoch (≤ 2^32 frames) under random 96-bit IVs. |
| D10 | Initial message is defined by the spec and authenticated under `SK`. | Handshake metadata transport is left to the application. If the initiator's first ratchet keys are sent alongside it in the clear, they are authenticated only implicitly (first frame fails to decrypt on mismatch). |

## 5. Open questions

1. **Root mixing vs. output combining (D1, D2).** Is `HKDF(salt = RK, ikm = DH ‖ ss)` a sound
   hybrid step, i.e. does the root chain keep forward secrecy and post-compromise security if
   either X25519 or ML-KEM (but not both) is broken? What is lost relative to keeping the PQ
   ratchet separate and combining message keys, beyond bandwidth?
2. **`SK` in two roles (D7).** `SK` is IKM for the header-key bootstrap and salt for the first
   root step. Is this acceptable under standard assumptions on HMAC, or should the handshake
   output 96 bytes and split them?
3. **Handshake binding (D4, D5).** Is binding only `IK_A ‖ IK_B` sufficient given ML-KEM's
   public-key binding, or should `info` carry a hash of the full prekey bundle, `EK_A`, `ct0`
   and both signing keys? Does signing raw, unlabelled key bytes create a practical confusion
   risk when the 32-byte and 1184-byte keys differ in length?
4. **Reuse of `PQSPK_B` as initial KEM ratchet key (3.1).** Two encapsulations per session
   against a long-lived, cross-session key. Any issue beyond the IND-CCA bound?
5. **Skipped-key retention (3.5).** FIFO eviction only. How much does the absence of time-based
   deletion weaken forward secrecy in practice?

## 6. Out of scope

Transport, prekey distribution, identity verification, session persistence, group messaging,
deniability claims, and side-channel resistance of the JavaScript runtime.
