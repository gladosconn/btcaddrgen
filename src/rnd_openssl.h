#ifndef __RND_OPENSSL_H__
#define __RND_OPENSSL_H__

#include <openssl/rand.h>

#include <vector>

namespace rnd {

int64_t GetPerformanceCounter();

template <int BUFF_SIZE>
class Rand_OpenSSL {
 public:
  Rand_OpenSSL() {
    memset(buff_, 0, BUFF_SIZE);
    int64_t counter = GetPerformanceCounter();
    RAND_add(&counter, sizeof(counter), 1.5);
    memset(&counter, 0, sizeof(counter));
  }

  const uint8_t *get_buff() const { return buff_; }
  int get_buff_size() const { return BUFF_SIZE; }

  void Rand() { RAND_bytes(buff_, BUFF_SIZE); }

 private:
  uint8_t buff_[BUFF_SIZE];
};

}  // namespace rnd

#endif
