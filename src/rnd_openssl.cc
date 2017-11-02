#include "rnd_openssl.h"

namespace rnd {

int64_t GetPerformanceCounter() {
// Read the hardware time stamp counter when available.
// See https://en.wikipedia.org/wiki/Time_Stamp_Counter for more information.
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
  return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
  uint64_t r = 0;
  __asm__ volatile("rdtsc"
                   : "=A"(r));  // Constrain the r variable to the eax:edx pair.
  return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
  uint64_t r1 = 0, r2 = 0;
  __asm__ volatile("rdtsc"
                   : "=a"(r1), "=d"(r2));  // Constrain r1 to rax and r2 to rdx.
  return (r2 << 32) | r1;
#else
  // Fall back to using C++11 clock (usually microsecond or nanosecond
  // precision)
  return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
}

}  // namespace rnd
