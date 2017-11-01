#ifndef __ECDSA_KEY_H__
#define __ECDSA_KEY_H__

#include <vector>

typedef std::vector<std::uint8_t> KeyData;

namespace ecdsa {

class KeyManager;

class Key {
public:
  explicit Key(KeyManager &key_man);

private:
  bool VerifyKey(const KeyData &key);
  void ECC_Start();
  void ECC_Stop();

private:
  KeyManager &key_man_;
  KeyData key_;
};

} // namespace ecdsa

#endif
