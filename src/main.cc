#include <fstream>
#include <iostream>
#include <memory>
#include <tuple>
#include <vector>

#include <openssl/sha.h>

#include <ecdsa/base58.h>
#include <ecdsa/key.h>

#include "args.h"
#include "btcaddr.h"
#include "btcwif.h"

#define BUFF_SIZE 1024

/**
 * Show help document.
 *
 * @param args The argument manager
 */
void ShowHelp(const Args &args) {
  std::cout << "BTCAddr(ess)Gen(erator)" << std::endl
            << "  An easy to use Bitcoin Address offline generator."
            << std::endl
            << std::endl;
  std::cout << "Usage:" << std::endl;
  std::cout << "  ./btcaddrgen [arguments...]" << std::endl << std::endl;
  std::cout << "Arguments:" << std::endl;
  std::cout << args.GetArgsHelpString() << std::endl;
}

std::tuple<std::vector<uint8_t>, bool> HashFile(const std::string &path) {
  std::vector<uint8_t> md;

  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    std::cerr << "Cannot open file " << path << std::endl;
    return std::make_tuple(md, false);
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
  md.resize(SHA512_DIGEST_LENGTH);
  SHA512_Final(md.data(), &ctx);

  return std::make_tuple(md, true);
}

std::tuple<std::vector<uint8_t>, bool> Signing(std::shared_ptr<ecdsa::Key> pkey,
                                               const std::string &path) {
  std::vector<uint8_t> signature;

  std::vector<uint8_t> md;
  bool succ;
  std::tie(md, succ) = HashFile(path);
  if (!succ) {
    return std::make_tuple(signature, false);
  }

  std::tie(signature, succ) = pkey->Sign(md);
  if (!succ) {
    std::cerr << "Cannot signing file!" << std::endl;
    return std::make_tuple(signature, false);
  }

  return std::make_tuple(signature, true);
}

bool Verifying(const ecdsa::PubKey &pub_key, const std::string &path,
               const std::vector<uint8_t> &signature) {
  std::vector<uint8_t> md;
  bool succ;
  std::tie(md, succ) = HashFile(path);
  if (succ) {
    return pub_key.Verify(md, signature);
  }
  return false;
}

void ShowKeyInfo(std::shared_ptr<ecdsa::Key> pkey) {
  auto pub_key = pkey->CreatePubKey();
  auto addr = btc::Address::FromPublicKey(pub_key.get_pub_key_data());
  std::cout << "Address: " << addr.ToString() << std::endl;
  std::cout << "Public key: " << base58::EncodeBase58(pkey->get_pub_key_data())
            << std::endl;
  std::cout << "Private key: "
            << base58::EncodeBase58(pkey->get_priv_key_data()) << std::endl;
  std::cout << "Private key(WIF): "
            << btc::wif::PrivateKeyToWif(pkey->get_priv_key_data())
            << std::endl;
}

/// Main program.
int main(int argc, const char *argv[]) {
  try {
    Args args(argc, argv);
    if (args.is_help()) {
      ShowHelp(args);
      return 0;
    }

    if (args.is_generate_new_key()) {
      ShowKeyInfo(std::make_shared<ecdsa::Key>());
      return 0;
    }

    // Import key.
    std::shared_ptr<ecdsa::Key> pkey;
    std::string priv_key_b58 = args.get_import_priv_key();
    if (!priv_key_b58.empty()) {
      std::vector<uint8_t> priv_key;
      // Checking WIF format.
      if (btc::wif::VerifyWifString(priv_key_b58)) {
        // Decoding private key in WIF format.
        priv_key = btc::wif::WifToPrivateKey(priv_key_b58);
      } else {
        // Decoding private key in plain base58 data.
        bool succ = base58::DecodeBase58(priv_key_b58.c_str(), priv_key);
        if (!succ) {
          std::cerr << "Failed to decode base58!" << std::endl;
          return 1;
        }
      }
      pkey = std::make_shared<ecdsa::Key>(priv_key);
      ShowKeyInfo(pkey);
    }

    // Signing file?
    if (!args.get_signing_file().empty()) {
      if (pkey == nullptr) {
        pkey = std::make_shared<ecdsa::Key>();
        ShowKeyInfo(pkey);
      }
      std::vector<uint8_t> signature;
      bool succ;
      std::tie(signature, succ) = Signing(pkey, args.get_signing_file());
      if (succ) {
        std::string signature_b58 = base58::EncodeBase58(signature);
        std::cout << "Signature: " << signature_b58 << std::endl;
        return 0;
      }
      return 1;
    }

    // Verifying
    if (!args.get_import_pub_key().empty() &&
        !args.get_verifying_file().empty() && !args.get_signature().empty()) {
      // Verifying
      std::vector<uint8_t> pub_key_data;
      bool succ = base58::DecodeBase58(args.get_import_pub_key(), pub_key_data);
      if (!succ) {
        std::cerr << "Cannot decode public key from base58 string."
                  << std::endl;
        return 1;
      }
      std::vector<uint8_t> signature;
      succ = base58::DecodeBase58(args.get_signature(), signature);
      if (!succ) {
        std::cerr << "Cannot decode signature from base58 string." << std::endl;
        return 1;
      }
      ecdsa::PubKey pub_key(pub_key_data);
      succ = Verifying(pub_key, args.get_verifying_file(), signature);
      if (succ) {
        std::cout << "Verified OK." << std::endl;
        return 0;
      }
      return 1;
    }

    if (priv_key_b58.empty()) {
      std::cerr << "No argument, -h to show help." << std::endl;
    }
    return 1;
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }

  return 0;
}
