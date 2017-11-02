#include "btcaddr.h"

#include <cstdint>

#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include "base58.h"

namespace btc {

std::vector<uint8_t> sha256(const uint8_t *data, int len) {
  // Prepare output data
  std::vector<uint8_t> md;
  md.resize(SHA256_DIGEST_LENGTH);

  // Calculate SHA256
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data, len);
  SHA256_Final(md.data(), &ctx);

  // Returns
  return md;
}

std::vector<uint8_t> ripemd160(const uint8_t *data, int len) {
  // Prepare output data
  std::vector<uint8_t> md;
  md.resize(RIPEMD160_DIGEST_LENGTH);

  // Calculate RIPEMD160
  RIPEMD160_CTX ctx;
  RIPEMD160_Init(&ctx);
  RIPEMD160_Update(&ctx, data, len);
  RIPEMD160_Final(md.data(), &ctx);

  return md;
}

Address Address::FromPublicKey(const ecdsa::KeyData &pub_key) {
  // 1. SHA256
  auto result = sha256(pub_key.data(), pub_key.size());

  // 2. RIPEMD160
  result = ripemd160(result.data(), result.size());

  // 3. Add 0x00 on front
  std::vector<uint8_t> temp;
  temp.resize(result.size() + 1);
  temp[0] = 0x00;
  memcpy(temp.data() + 1, result.data(), result.size());
  result = temp;

  // 4. SHA256 twice
  result = sha256(result.data(), result.size());
  result = sha256(result.data(), result.size());

  // 5. Take first 4 bytes only and add to temp
  std::vector<uint8_t> long_result;
  long_result.resize(temp.size() + 4);
  memcpy(long_result.data(), temp.data(), temp.size());
  memcpy(long_result.data() + temp.size(), result.data(), 4);

  // 6. Base58
  Address addr;
  addr.addr_str_ = base58::EncodeBase58(long_result);

  // Returns address object
  return addr;
}

}  // namespace btc
