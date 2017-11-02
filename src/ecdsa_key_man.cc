#include "ecdsa_key_man.h"

#include <cassert>

#include <vector>

//#include "randkey.h"
#include "rnd_man.h"
#include "rnd_openssl.h"
#include "rnd_os.h"

namespace ecdsa {

KeyManager &KeyManager::get_instance() {
  static KeyManager instance;
  return instance;
}

KeyManager::KeyManager() { ECC_Start(); }

KeyManager::~KeyManager() { ECC_Stop(); }

Key KeyManager::NewKey() { return Key(*this); }

void KeyManager::ECC_Start() {
  assert(secp256k1_context_sign_ == nullptr);

  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  assert(ctx != nullptr);

  {
    // Pass in a random blinding seed to the secp256k1 context.
    rnd::RandManager rnd_man(32);
    rnd_man.Begin();
    rnd_man.Rand<rnd::Rand_OS>();
    std::vector<uint8_t> vseed = rnd_man.End();
    bool ret = secp256k1_context_randomize(ctx, vseed.data());
    assert(ret);
  }

  secp256k1_context_sign_ = ctx;
}

void KeyManager::ECC_Stop() {
  secp256k1_context *ctx = secp256k1_context_sign_;
  secp256k1_context_sign_ = nullptr;

  if (ctx) {
    secp256k1_context_destroy(ctx);
  }
}

}  // namespace ecdsa
