#ifndef __BTC_ADDR_H__
#define __BTC_ADDR_H__

#include <stdlib.h>
#include <cstdlib>

#include <string>
#include <vector>

namespace btc {

class Address {
 public:
  /**
   * Convert a public key to address.
   *
   * @param pub_key Public key.
   * @param prefix_char Prefix character for address.
   * @param out_hash160 Hash160 data.
   *
   * @return New generated address object.
   */
  static Address FromPublicKey(const std::vector<uint8_t> &pub_key,
                               unsigned char prefix_char,
                               unsigned char *out_hash160 = nullptr);

  /// Convert address object to string
  std::string ToString() const { return addr_str_; }

 private:
  Address() {}

 private:
  std::string addr_str_;
};

}  // namespace btc

#endif
