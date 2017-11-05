#include <iostream>
#include <memory>
#include <fstream>

#include <openssl/sha.h>

#include <ecdsa/base58.h>
#include <ecdsa/key.h>

#include "args.h"
#include "btcaddr.h"

#define BUFF_SIZE 1024

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
  try {
    Args args(argc, argv);
    if (args.is_help()) {
      ShowHelp(args);
      return 0;
    }

    // Import key.
    std::shared_ptr<ecdsa::Key> pkey;
    std::string priv_key_b58 = args.get_import_priv_key();
    if (!priv_key_b58.empty()) {
      std::vector<uint8_t> priv_key;
      bool succ = base58::DecodeBase58(priv_key_b58.c_str(), priv_key);
      if (!succ) {
        std::cerr << "Failed to decode base58!" << std::endl;
        return 1;
      }
      pkey.reset(new ecdsa::Key(priv_key));
    } else {
      pkey.reset(new ecdsa::Key());
    }

    auto pub_key = pkey->CreatePubKey();
    auto addr = btc::Address::FromPublicKey(pub_key.get_pub_key_data());
    std::cout << "Address: " << addr.ToString() << std::endl;
    std::cout << "Public key: "
      << base58::EncodeBase58(pkey->get_pub_key_data())
      << std::endl;
    std::cout << "Private key: "
      << base58::EncodeBase58(pkey->get_priv_key_data())
      << std::endl;

    // Signing file?
    std::string signing_file_str = args.get_signing_file();
    if (!signing_file_str.empty()) {
      std::ifstream input(signing_file_str, std::ios::binary);
      if (!input.is_open()) {
        std::cerr << "Cannot open file " << signing_file_str << std::endl;
        return 1;
      }

      // Hash file contents
      SHA512_CTX ctx;
      SHA512_Init(&ctx);

      // Reading...
      char buff[BUFF_SIZE];
      while (!input.eof()) {
        input.read(buff, BUFF_SIZE);
        size_t buff_size = input.gcount();
        SHA512_Update(&ctx, buff, buff_size);
      }

      // Get md buffer.
      std::vector<uint8_t> md(SHA512_DIGEST_LENGTH);
      SHA512_Final(md.data(), &ctx);

      std::vector<uint8_t> sign;
      bool succ;
      std::tie(sign, succ) = pkey->Sign(md);
      if (!succ) {
        std::cerr << "Cannot signing file!" << std::endl;
        return 1;
      }

      std::cout << "Sign: " << base58::EncodeBase58(sign) << std::endl;
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }

  return 0;
}
