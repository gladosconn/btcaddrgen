#include "ecdsa_key.h"

#include <cassert>

#include "secp256k1.h"

#include "ecdsa_key_man.h"
#include "randkey.h"

namespace ecdsa {

Key::Key(KeyManager &key_man) : key_man_(key_man) {
  key_.resize(32);
  do {
    rnd::GetStrongRandBytes(key_.data(), key_.size());
  } while (!VerifyKey(key_));
}

bool Key::VerifyKey(const KeyData &key) {
  return secp256k1_ec_seckey_verify(key_man_.get_context_sign(), key.data());
}

} // namespace ecdsa
