#ifndef __ECDSA_KEY_H__
#define __ECDSA_KEY_H__

#include <vector>

typedef std::vector<std::uint8_t> KeyData;

class ECDSAKey {
public:
  ECDSAKey();

private:
  static bool VerifyKey(const KeyData &key);

private:
  KeyData key_;
};

#endif
