#include "btcwif.h"

#include <cassert>

#include <ecdsa/base58.h>

#include "utils.h"

namespace btc {
namespace wif {

std::string PrivateKeyToWif(const std::vector<uint8_t> &priv_key) {
  // 0. Preparing...
  std::vector<uint8_t> pk2(priv_key.size() + 1);

  // 1. 0x80 to front.
  pk2[0] = 0x80;
  memcpy(pk2.data() + 1, priv_key.data(), priv_key.size());

  // 2. 0x01 to back.
  pk2.push_back(0x01);

  // 3. Perform SHA256 on extended key.
  std::vector<uint8_t> check_sum_half = utils::sha256(pk2.data(), pk2.size());
  std::vector<uint8_t> check_sum =
      utils::sha256(check_sum_half.data(), check_sum_half.size());

  // 4. Add 4 bytes from check sum to pk2.
  std::vector<uint8_t> pk4(pk2.size() + 4);
  memcpy(pk4.data(), pk2.data(), pk2.size());
  memcpy(pk4.data() + pk2.size(), check_sum.data(), 4);

  // 5. Base58
  return base58::EncodeBase58(pk4);
}

std::vector<uint8_t> WifToPrivateKey(const std::string &priv_key_str) {
  // 1. Revert base58 to data.
  std::vector<uint8_t> pk1;
  assert(base58::DecodeBase58(priv_key_str, pk1));

  // 2. Calculate size.
  size_t size;
  size_t add_index = pk1.size() - 4;
  if (pk1[add_index] == 0x01) {
    size = pk1.size() - 6;
  } else {
    size = pk1.size() - 5;
  }

  // 3. Remove first 1 byte, last 4 byte(s) and
  //   last 1 byte if it equals to 0x01.
  std::vector<uint8_t> pk2(size);
  memcpy(pk2.data(), pk1.data() + 1, size);

  return pk2;
}

bool VerifyWifString(const std::string &priv_key_str) {
  std::vector<uint8_t> priv_key_data;
  bool succ = base58::DecodeBase58(priv_key_str, priv_key_data);
  if (!succ) return false;

  std::vector<uint8_t> last_4_bytes(4);
  memcpy(last_4_bytes.data(), priv_key_data.data() + (priv_key_data.size() - 4),
         4);

  std::vector<uint8_t> priv_key_data_to_hash(priv_key_data.size() - 4);
  memcpy(priv_key_data_to_hash.data(), priv_key_data.data(),
         priv_key_data.size());

  std::vector<uint8_t> check_sum_half =
      utils::sha256(priv_key_data_to_hash.data(), priv_key_data_to_hash.size());
  std::vector<uint8_t> check_sum =
      utils::sha256(check_sum_half.data(), check_sum_half.size());

  return memcmp(check_sum.data(), last_4_bytes.data(), 4) == 0;
}

}  // namespace wif
}  // namespace btc
