#ifndef __ECDSA_KEY_MAN_H__
#define __ECDSA_KEY_MAN_H__

#include "secp256k1.h"

#include "ecdsa_key.h"

namespace ecdsa {

class KeyManager {
 public:
  static KeyManager &get_instance();
  ~KeyManager();

  secp256k1_context *get_context_sign() { return secp256k1_context_sign_; }

  Key NewKey();

 private:
  KeyManager();

  void ECC_Start();
  void ECC_Stop();

 private:
  secp256k1_context *secp256k1_context_sign_ = nullptr;
};

}  // namespace ecdsa

#endif
