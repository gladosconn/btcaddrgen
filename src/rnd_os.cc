#include "rnd_os.h"

#include <fstream>
#include <stdexcept>

namespace rnd {

[[noreturn]] static void RandFailure() {
  throw std::runtime_error("Failed to read randomness, aborting");
}

#ifndef WIN32
/** Fallback: get 32 bytes of system entropy from /dev/urandom. The most
 * compatible way to get cryptographic randomness on UNIX-ish platforms.
 */
void GetDevURandom(unsigned char *ent32) {
  std::ifstream f("/dev/urandom", std::ios::binary);
  if (!f.is_open()) {
    RandFailure();
  }
  int have = 0;
  do {
    f.read((char *)ent32 + have, NUM_OS_RANDOM_BYTES - have);
    ssize_t n = f.gcount();
    if (n <= 0 || n + have > NUM_OS_RANDOM_BYTES) {
      f.close();
      RandFailure();
    }
    have += n;
  } while (have < NUM_OS_RANDOM_BYTES);
}
#endif

void GetOSRand(unsigned char *ent32) {
#if defined(WIN32)
  HCRYPTPROV hProvider;
  int ret = CryptAcquireContextW(&hProvider, nullptr, nullptr, PROV_RSA_FULL,
                                 CRYPT_VERIFYCONTEXT);
  if (!ret) {
    RandFailure();
  }
  ret = CryptGenRandom(hProvider, NUM_OS_RANDOM_BYTES, ent32);
  if (!ret) {
    RandFailure();
  }
  CryptReleaseContext(hProvider, 0);
#elif defined(HAVE_SYS_GETRANDOM)
  /* Linux. From the getrandom(2) man page:
   * "If the urandom source has been initialized, reads of up to 256 bytes
   * will always return as many bytes as requested and will not be
   * interrupted by signals."
   */
  int rv = syscall(SYS_getrandom, ent32, NUM_OS_RANDOM_BYTES, 0);
  if (rv != NUM_OS_RANDOM_BYTES) {
    if (rv < 0 && errno == ENOSYS) {
      /* Fallback for kernel <3.17: the return value will be -1 and errno
       * ENOSYS if the syscall is not available, in that case fall back
       * to /dev/urandom.
       */
      GetDevURandom(ent32);
    } else {
      RandFailure();
    }
  }
#elif defined(HAVE_GETENTROPY) && defined(__OpenBSD__)
  /* On OpenBSD this can return up to 256 bytes of entropy, will return an
   * error if more are requested.
   * The call cannot return less than the requested number of bytes.
     getentropy is explicitly limited to openbsd here, as a similar (but not
     the same) function may exist on other platforms via glibc.
   */
  if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
    RandFailure();
  }
#elif defined(HAVE_GETENTROPY_RAND) && defined(MAC_OSX)
  // We need a fallback for OSX < 10.12
  if (&getentropy != nullptr) {
    if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
      RandFailure();
    }
  } else {
    GetDevURandom(ent32);
  }
#elif defined(HAVE_SYSCTL_ARND)
  /* FreeBSD and similar. It is possible for the call to return less
   * bytes than requested, so need to read in a loop.
   */
  static const int name[2] = {CTL_KERN, KERN_ARND};
  int have = 0;
  do {
    size_t len = NUM_OS_RANDOM_BYTES - have;
    if (sysctl(name, ARRAYLEN(name), ent32 + have, &len, nullptr, 0) != 0) {
      RandFailure();
    }
    have += len;
  } while (have < NUM_OS_RANDOM_BYTES);
#else
  /* Fall back to /dev/urandom if there is no specific method implemented to
   * get system entropy for this OS.
   */
  GetDevURandom(ent32);
#endif
}

void Rand_OS::Rand() { GetOSRand(buff_); }

}  // namespace rnd
