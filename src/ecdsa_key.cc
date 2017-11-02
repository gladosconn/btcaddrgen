#include "ecdsa_key.h"

#include <cassert>

#include "secp256k1.h"

#include "ecdsa_key_man.h"

#include "rnd_man.h"
#include "rnd_openssl.h"
#include "rnd_os.h"

namespace ecdsa {

const unsigned int PRIVATE_KEY_STORE_SIZE = 32;
const unsigned int PRIVATE_KEY_SIZE = 279;
const unsigned int PUBLIC_KEY_SIZE = 65;
const unsigned int SIGNATURE_SIZE = 72;

Key::Key(KeyManager &key_man) : key_man_(key_man) {
  do {
    rnd::RandManager rnd_man(PRIVATE_KEY_STORE_SIZE);
    rnd_man.Begin();
    rnd_man.Rand<rnd::Rand_OpenSSL<128>>();
    rnd_man.Rand<rnd::Rand_OS>();
    key_ = rnd_man.End();
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

}  // namespace ecdsa
