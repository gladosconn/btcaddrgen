#include "base58.h"

#include <cassert>

#include <string>
#include <vector>

namespace base58 {

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char *BASE58_CHARS =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string EncodeBase58(const unsigned char *pbegin,
                         const unsigned char *pend) {
  // Skip & count leading zeroes.
  int zeroes = 0;
  int length = 0;
  while (pbegin != pend && *pbegin == 0) {
    pbegin++;
    zeroes++;
  }
  // Allocate enough space in big-endian base58 representation.
  int size =
      (pend - pbegin) * 138 / 100 + 1;  // log(256) / log(58), rounded up.
  std::vector<unsigned char> b58(size);
  // Process the bytes.
  while (pbegin != pend) {
    int carry = *pbegin;
    int i = 0;
    // Apply "b58 = b58 * 256 + ch".
    for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin();
         (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
      carry += 256 * (*it);
      *it = carry % 58;
      carry /= 58;
    }

    assert(carry == 0);
    length = i;
    pbegin++;
  }
  // Skip leading zeroes in base58 result.
  std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
  while (it != b58.end() && *it == 0) it++;
  // Translate the result into a string.
  std::string str;
  str.reserve(zeroes + (b58.end() - it));
  str.assign(zeroes, '1');
  while (it != b58.end()) str += BASE58_CHARS[*(it++)];
  return str;
}

bool DecodeBase58(const char *psz, std::vector<unsigned char> &vch) {
  // Skip leading spaces.
  while (*psz && isspace(*psz)) psz++;
  // Skip and count leading '1's.
  int zeroes = 0;
  int length = 0;
  while (*psz == '1') {
    zeroes++;
    psz++;
  }
  // Allocate enough space in big-endian base256 representation.
  int size = strlen(psz) * 733 / 1000 + 1;  // log(58) / log(256), rounded up.
  std::vector<unsigned char> b256(size);
  // Process the characters.
  while (*psz && !isspace(*psz)) {
    // Decode base58 character
    const char *ch = strchr(BASE58_CHARS, *psz);
    if (ch == nullptr) return false;
    // Apply "b256 = b256 * 58 + ch".
    int carry = ch - BASE58_CHARS;
    int i = 0;
    for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin();
         (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
      carry += 58 * (*it);
      *it = carry % 256;
      carry /= 256;
    }
    assert(carry == 0);
    length = i;
    psz++;
  }
  // Skip trailing spaces.
  while (isspace(*psz)) psz++;
  if (*psz != 0) return false;
  // Skip leading zeroes in b256.
  std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
  while (it != b256.end() && *it == 0) it++;
  // Copy result into output vector.
  vch.reserve(zeroes + (b256.end() - it));
  vch.assign(zeroes, 0x00);
  while (it != b256.end()) vch.push_back(*(it++));
  return true;
}

std::string EncodeBase58(const std::vector<unsigned char> &vch) {
  return EncodeBase58(vch.data(), vch.data() + vch.size());
}

bool DecodeBase58(const std::string &str, std::vector<unsigned char> &vchRet) {
  return DecodeBase58(str.c_str(), vchRet);
}

}  // namespace base58
