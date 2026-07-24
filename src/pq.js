// Thin wrapper over @noble/post-quantum's ML-KEM-768 -- the one primitive category WebCrypto
// doesn't yet expose natively. Kept as its own seam (mirroring primitives.js for WebCrypto) so
// x3dh.js and ratchet.js don't each couple directly to the noble package's API shape.
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

export function generatePqKeyPair() {
  return ml_kem768.keygen();
}

export function pqEncapsulate(publicKey) {
  return ml_kem768.encapsulate(publicKey);
}

export function pqDecapsulate(cipherText, secretKey) {
  return ml_kem768.decapsulate(cipherText, secretKey);
}
