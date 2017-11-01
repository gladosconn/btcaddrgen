#include "randkey.h"

#include <cassert>
#include <fstream>

#include <openssl/rand.h>

#include "crypto/common.h"
#include "crypto/sha512.h"

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#include <cpuid.h>
#endif

namespace rnd {

static inline int64_t GetPerformanceCounter() {
// Read the hardware time stamp counter when available.
// See https://en.wikipedia.org/wiki/Time_Stamp_Counter for more information.
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
  return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
  uint64_t r = 0;
  __asm__ volatile("rdtsc"
                   : "=A"(r)); // Constrain the r variable to the eax:edx pair.
  return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
  uint64_t r1 = 0, r2 = 0;
  __asm__ volatile("rdtsc"
                   : "=a"(r1), "=d"(r2)); // Constrain r1 to rax and r2 to rdx.
  return (r2 << 32) | r1;
#else
  // Fall back to using C++11 clock (usually microsecond or nanosecond
  // precision)
  return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
}

void RandAddSeed() {
  // Seed with CPU performance counter
  int64_t nCounter = GetPerformanceCounter();
  RAND_add(&nCounter, sizeof(nCounter), 1.5);
  memset(&nCounter, 0, sizeof(nCounter));
}

[[noreturn]] static void RandFailure() {
  throw std::runtime_error("Failed to read randomness, aborting");
}

static const int NUM_OS_RANDOM_BYTES = 32;

#ifndef WIN32
/** Fallback: get 32 bytes of system entropy from /dev/urandom. The most
 * compatible way to get cryptographic randomness on UNIX-ish platforms.
 */
void GetDevURandom(unsigned char *ent32) {
  std::ifstream f("/dev/urandom", std::ios::binary);
  if (!f.is_open()) {
    RandFailure();
  }
  // int f = open("/dev/urandom", O_RDONLY);
  // if (f == -1) {
  //     RandFailure();
  // }
  int have = 0;
  do {
    f.read((char *)ent32 + have, NUM_OS_RANDOM_BYTES - have);
    ssize_t n = f.gcount();
    // ssize_t n = read(f, ent32 + have, NUM_OS_RANDOM_BYTES - have);
    if (n <= 0 || n + have > NUM_OS_RANDOM_BYTES) {
      // close(f);
      f.close();
      RandFailure();
    }
    have += n;
  } while (have < NUM_OS_RANDOM_BYTES);
  // close(f);
}
#endif

static void RandAddSeedPerfmon() {
  RandAddSeed();

#ifdef WIN32
  // Don't need this on Linux, OpenSSL automatically uses /dev/urandom
  // Seed with the entire set of perfmon data

  // This can take up to 2 seconds, so only do it every 10 minutes
  static int64_t nLastPerfmon;
  if (GetTime() < nLastPerfmon + 10 * 60)
    return;
  nLastPerfmon = GetTime();

  std::vector<unsigned char> vData(250000, 0);
  long ret = 0;
  unsigned long nSize = 0;
  const size_t nMaxSize =
      10000000; // Bail out at more than 10MB of performance data
  while (true) {
    nSize = vData.size();
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", nullptr, nullptr,
                           vData.data(), &nSize);
    if (ret != ERROR_MORE_DATA || vData.size() >= nMaxSize)
      break;
    vData.resize(std::max((vData.size() * 3) / 2,
                          nMaxSize)); // Grow size of buffer exponentially
  }
  RegCloseKey(HKEY_PERFORMANCE_DATA);
  if (ret == ERROR_SUCCESS) {
    RAND_add(vData.data(), nSize, nSize / 100.0);
    memory_cleanse(vData.data(), nSize);
    LogPrint(BCLog::RAND, "%s: %lu bytes\n", __func__, nSize);
  } else {
    static bool warned = false; // Warn only once
    if (!warned) {
      LogPrintf("%s: Warning: RegQueryValueExA(HKEY_PERFORMANCE_DATA) failed "
                "with code %i\n",
                __func__, ret);
      warned = true;
    }
  }
#endif
}

void GetRandBytes(unsigned char *buf, int num) {
  if (RAND_bytes(buf, num) != 1) {
    RandFailure();
  }
}

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

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
static std::atomic<bool> hwrand_initialized{false};
static bool rdrand_supported = false;
static constexpr uint32_t CPUID_F1_ECX_RDRAND = 0x40000000;
static void RDRandInit() {
  uint32_t eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & CPUID_F1_ECX_RDRAND)) {
    // TODO maybe show some message here?
    rdrand_supported = true;
  }
  hwrand_initialized.store(true);
}
#else
static void RDRandInit() {}
#endif

static bool GetHWRand(unsigned char *ent32) {
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
  assert(hwrand_initialized.load(std::memory_order_relaxed));
  if (rdrand_supported) {
    uint8_t ok;
// Not all assemblers support the rdrand instruction, write it in hex.
#ifdef __i386__
    for (int iter = 0; iter < 4; ++iter) {
      uint32_t r1, r2;
      __asm__ volatile(".byte 0x0f, 0xc7, 0xf0;" // rdrand %eax
                       ".byte 0x0f, 0xc7, 0xf2;" // rdrand %edx
                       "setc %2"
                       : "=a"(r1), "=d"(r2), "=q"(ok)::"cc");
      if (!ok)
        return false;
      WriteLE32(ent32 + 8 * iter, r1);
      WriteLE32(ent32 + 8 * iter + 4, r2);
    }
#else
    uint64_t r1, r2, r3, r4;
    __asm__ volatile(".byte 0x48, 0x0f, 0xc7, 0xf0, " // rdrand %rax
                     "0x48, 0x0f, 0xc7, 0xf3, "       // rdrand %rbx
                     "0x48, 0x0f, 0xc7, 0xf1, "       // rdrand %rcx
                     "0x48, 0x0f, 0xc7, 0xf2; "       // rdrand %rdx
                     "setc %4"
                     : "=a"(r1), "=b"(r2), "=c"(r3), "=d"(r4), "=q"(ok)::"cc");
    if (!ok)
      return false;
    WriteLE64(ent32, r1);
    WriteLE64(ent32 + 8, r2);
    WriteLE64(ent32 + 16, r3);
    WriteLE64(ent32 + 24, r4);
#endif
    return true;
  }
#endif
  return false;
}

static std::mutex cs_rng_state;
static unsigned char rng_state[32] = {0};
static uint64_t rng_counter = 0;

void GetStrongRandBytes(unsigned char *out, int num) {
  assert(num <= 32);
  CSHA512 hasher;
  unsigned char buf[64];

  // First source: OpenSSL's RNG
  RandAddSeedPerfmon();
  GetRandBytes(buf, 32);
  hasher.Write(buf, 32);

  // Second source: OS RNG
  GetOSRand(buf);
  hasher.Write(buf, 32);

  // Third source: HW RNG, if available.
  if (GetHWRand(buf)) {
    hasher.Write(buf, 32);
  }

  // Combine with and update state
  {
    std::unique_lock<std::mutex> lock(cs_rng_state);
    hasher.Write(rng_state, sizeof(rng_state));
    hasher.Write((const unsigned char *)&rng_counter, sizeof(rng_counter));
    ++rng_counter;
    hasher.Finalize(buf);
    memcpy(rng_state, buf + 32, 32);
  }

  // Produce output
  memcpy(out, buf, num);
  memset(buf, 0, 64);
}

} // namespace
