#include "rnd_man.h"

namespace rnd {

RandManager::RandManager(int buff_size) : buff_size_(buff_size) {}

void RandManager::Begin() { SHA512_Init(&sha_ctx_); }

std::vector<uint8_t> RandManager::End() {
  SHA512_Final(md_, &sha_ctx_);
  std::vector<uint8_t> result;
  result.resize(buff_size_);
  memcpy(result.data(), md_, buff_size_);
  return result;
}

void RandManager::HashBuff(const uint8_t *buff, int size) {
  SHA512_Update(&sha_ctx_, buff, size);
}

}  // namespace rnd
