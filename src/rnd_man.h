#ifndef __RND_MAN_H__
#define __RND_MAN_H__

#include <cstdint>
#include <vector>

#include <openssl/sha.h>

namespace rnd {

/**
 * Rand number manager
 */
class RandManager {
 public:
  /**
   * Constructor of RandManager
   *
   * @param buff_size Setup how many bytes want rand
   */
  explicit RandManager(int buff_size = 32);

  /// Begin new hash rand.
  void Begin();

  /// Stop hash rand and returns rand buffer.
  std::vector<uint8_t> End();

  /// Rand with a rand operator.
  template <typename RandOpt>
  void Rand() {
    // Create rand operator
    RandOpt rand;
    rand.Rand();

    // Get randomized buffer
    const uint8_t *rnd_result = rand.get_buff();
    int rnd_result_size = rand.get_buff_size();

    // Hash buffer
    HashBuff(rnd_result, rnd_result_size);
  }

 private:
  void HashBuff(const uint8_t *buff, int size);

 private:
  int buff_size_;
  SHA512_CTX sha_ctx_;
  uint8_t md_[SHA512_DIGEST_LENGTH];
};

}  // namespace rnd

#endif
