#include "ecdsa_key.h"

#include "randkey.h"

ECDSAKey::ECDSAKey() {
  key_.resize(32);
  do {
    rnd::GetStrongRandBytes(key_.data(), key_.size());
  } while (!VerifyKey(key_));
}

bool ECDSAKey::VerifyKey(const KeyData &key) {
  return secp256k1_ec_seckey_verify(secp256k1_context_sign, key.data());
}
