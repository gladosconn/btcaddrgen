#include <boost/program_options.hpp>
#include <iostream>

#include "args.h"
#include "base58.h"
#include "ecdsa_key_man.h"

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
  auto &man = ecdsa::KeyManager::get_instance();
  auto key = man.NewKey();
  std::cout << "public key: "
            << base58::EncodeBase58(key.CalculatePublicKey(true)) << std::endl;
  std::cout << "private key: " << base58::EncodeBase58(key.get_key())
            << std::endl;

  return 0;
}
