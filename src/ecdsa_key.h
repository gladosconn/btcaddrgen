#ifndef __ECDSA_KEY_H__
#define __ECDSA_KEY_H__

#include <vector>

namespace ecdsa {

typedef std::vector<std::uint8_t> KeyData;

class KeyManager;

class Key {
 public:
  /**
   * Allocate Key object.
   *
   * @param key_man KeyManager object reference.
   * @param compressed True if key is compressed.
   */
  explicit Key(KeyManager &key_man);

  /// Get private key.
  KeyData get_key() const;

  /// Calculate public key.
  KeyData CalculatePublicKey(bool compressed) const;

 private:
  bool VerifyKey(const KeyData &key);
  void ECC_Start();
  void ECC_Stop();

 private:
  KeyManager &key_man_;
  KeyData key_;
  KeyData pub_key_;
};

}  // namespace ecdsa

#endif
