#ifndef __RND_OS_H__
#define __RND_OS_H__

#include <cstdint>

namespace rnd {

const int NUM_OS_RANDOM_BYTES = 32;

class Rand_OS {
 public:
  const uint8_t *get_buff() const { return buff_; }
  int get_buff_size() const { return NUM_OS_RANDOM_BYTES; }

  void Rand();

 private:
  uint8_t buff_[NUM_OS_RANDOM_BYTES];
};

}  // namespace rnd

#endif
