#ifndef __ECDSA_KEY_H__
#define __ECDSA_KEY_H__

#include <vector>

namespace ecdsa {

typedef std::vector<std::uint8_t> KeyData;

class KeyManager;

const unsigned int PRIVATE_KEY_SIZE = 279;
const unsigned int PUBLIC_KEY_SIZE = 65;
const unsigned int SIGNATURE_SIZE = 72;

class Key {
public:
  explicit Key(KeyManager &key_man);

  KeyData get_priv_key() const;

  KeyData get_pub_key() const;

private:
  bool VerifyKey(const KeyData &key);
  void ECC_Start();
  void ECC_Stop();

  KeyData CalcPrivateKey();
  KeyData CalcPublicKey();

private:
  KeyManager &key_man_;
  KeyData key_;
  KeyData priv_key_;
  KeyData pub_key_;
  bool compressed_ = true;
};

} // namespace ecdsa

#endif
