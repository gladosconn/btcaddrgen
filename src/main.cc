#include <iostream>

#include <ecdsa/base58.h>
#include <ecdsa/key.h>

#include "args.h"
#include "btcaddr.h"

/**
 * Show help document.
 *
 * @param args The argument manager
 */
void ShowHelp(const Args &args) {
  std::cout << "BTCAddrGen version 0.1" << std::endl;
  std::cout << "Usage:" << std::endl;
  std::cout << "  ./btcaddrgen" << std::endl << std::endl;
  std::cout << "Arguments:" << std::endl;
  std::cout << args.GetArgsHelpString() << std::endl;
}

/// Main program.
int main(int argc, const char *argv[]) {
  Args args(argc, argv);
  if (args.is_help()) {
    ShowHelp(args);
    return 0;
  }

  // Trying to generate a new key pair.
  ecdsa::Key key;

  auto pub_key = key.CreatePubKey();
  auto addr = btc::Address::FromPublicKey(pub_key.get_pub_key_data());
  std::cout << "address: " << addr.ToString() << std::endl;
  std::cout << "public key: " << base58::EncodeBase58(key.get_pub_key_data()) << std::endl;
  std::cout << "private key: " << base58::EncodeBase58(key.get_priv_key_data())
            << std::endl;

  return 0;
}
