#ifndef __BTC_WIF_H__
#define __BTC_WIF_H__

#include <string>
#include <vector>

namespace btc {
namespace wif {

/**
 * Convert private key to string in WIF
 *
 * @param priv_key Private key data.
 *
 * @return WIF string.
 */
std::string PrivateKeyToWif(const std::vector<uint8_t> &priv_key);

/**
 * Parse WIF private key string.
 *
 * @param priv_key_str Private key string in WIF format.
 *
 * @return Private key data.
 */
std::vector<uint8_t> WifToPrivateKey(const std::string &priv_key_str);

/**
 * Verifying a private key string in WIF format.
 *
 * @param priv_key_str Private key string in WIF format.
 *
 * @return Returns true if the private key string is in WIF format and valid.
 */
bool VerifyWifString(const std::string &priv_key_str);

}  // namespace wif
}  // namespace btc

#endif
