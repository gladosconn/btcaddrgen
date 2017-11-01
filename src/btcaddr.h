#ifndef __BTC_ADDR_H__
#define __BTC_ADDR_H__

#include <string>

#include "ecdsa_key.h"

namespace btc {

class Address {
public:
  /**
   * Convert a public key to address.
   *
   * @param pub_key Public key.
   *
   * @return New generated address object.
   */
  static Address FromPublicKey(const ecdsa::KeyData &pub_key);

  /// Convert address object to string
  std::string ToString() const { return addr_str_; }

private:
  Address() {}

private:
  std::string addr_str_;
};

} // namespace btc

#endif
