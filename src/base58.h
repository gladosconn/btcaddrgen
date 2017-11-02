#ifndef __BASE58_H__
#define __BASE58_H__

#include <string>
#include <vector>

namespace base58 {

std::string EncodeBase58(const unsigned char *pbegin,
                         const unsigned char *pend);

bool DecodeBase58(const char *psz, std::vector<unsigned char> &vch);

std::string EncodeBase58(const std::vector<unsigned char> &vch);

bool DecodeBase58(const std::string &str, std::vector<unsigned char> &vchRet);

}  // namespace base58

#endif
