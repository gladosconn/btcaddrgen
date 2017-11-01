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

KeyData Key::get_key() const { return key_; }

KeyData Key::CalculatePublicKey(bool compressed) const {
  secp256k1_pubkey pubkey;
  size_t clen = PUBLIC_KEY_SIZE;
  KeyData result;
  result.resize(clen);
  int ret = secp256k1_ec_pubkey_create(key_man_.get_context_sign(), &pubkey,
                                       key_.data());
  assert(ret);
  secp256k1_ec_pubkey_serialize(
      key_man_.get_context_sign(), result.data(), &clen, &pubkey,
      compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  result.resize(clen);
  return result;
}

bool Key::VerifyKey(const KeyData &key) {
  return secp256k1_ec_seckey_verify(key_man_.get_context_sign(), key.data());
}

} // namespace ecdsa
