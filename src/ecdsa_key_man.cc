#include "ecdsa_key_man.h"

#include <cassert>

#include <vector>

#include "randkey.h"

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
    std::vector<unsigned char> vseed(32);
    rnd::GetRandBytes(vseed.data(), 32);
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

} // namespace
