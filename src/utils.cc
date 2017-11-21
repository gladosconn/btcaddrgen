#include "utils.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>

namespace utils {

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

}  // namespace utils
