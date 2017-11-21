#ifndef __BTC_WIF_H__
#define __BTC_WIF_H__

#include <string>
#include <vector>

namespace btc {
namespace wif {

std::string PrivateKeyToWif(const std::vector<uint8_t> &priv_key);

std::vector<uint8_t> WifToPrivateKey(const std::string &priv_key_str);

}  // namespace wif
}  // namespace btc

#endif
