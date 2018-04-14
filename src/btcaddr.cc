#include "btcaddr.h"

#include <stdlib.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <ecdsa/base58.h>

#include "utils.h"

namespace btc {

Address Address::FromPublicKey(const std::vector<uint8_t> &pub_key,
                               unsigned char prefix_char,
                               unsigned char *out_hash160) {
  // 1. SHA256
  auto result = utils::sha256(pub_key.data(), pub_key.size());

  // 2. RIPEMD160
  result = utils::ripemd160(result.data(), result.size());

  // 3. Add 0x00 on front
  std::vector<uint8_t> temp;
  temp.resize(result.size() + 1);
  temp[0] = prefix_char;
  std::memcpy(temp.data() + 1, result.data(), result.size());
  result = temp;

  // 4. SHA256 twice
  result = utils::sha256(result.data(), result.size());
  result = utils::sha256(result.data(), result.size());

  // 5. Take first 4 bytes only and add to temp
  std::vector<uint8_t> long_result;
  long_result.resize(temp.size() + 4);
  memcpy(long_result.data(), temp.data(), temp.size());
  memcpy(long_result.data() + temp.size(), result.data(), 4);

  // Copying hash160 if required.
  if (out_hash160) {
      memcpy(out_hash160, long_result.data() + 1, 20);
  }

  // 6. Base58
  Address addr;
  addr.addr_str_ = base58::EncodeBase58(long_result);

  // Returns address object
  return addr;
}

}  // namespace btc
