#ifndef __UTILS_H__
#define __UTILS_H__

#include <vector>

namespace utils {

std::vector<uint8_t> ripemd160(const uint8_t *data, int len);

std::vector<uint8_t> sha256(const uint8_t *data, int len);

}  // namespace utils

#endif
