#ifndef __ARGS_H__
#define __ARGS_H__

#include <boost/program_options.hpp>
namespace po = boost::program_options;

/// Argument manager.
class Args {
 public:
  /**
   * Initialize arguments.
   */
  Args(int argc, const char *argv[]);

  /// --help is provided.
  bool is_help() const { return is_help_; }

  /// Returns import private key.
  std::string get_import_priv_key() const { return import_priv_key_; }

  /// Returns import public key.
  std::string get_import_pub_key() const { return import_pub_key_; }

  /// Return siging file.
  std::string get_signing_file() const { return signing_file_; }

  /// Returns verifying file.
  std::string get_verifying_file() const { return verifying_file_; }

  /// Get signature for verifying.
  std::string get_signature() const { return signature_; }

  /// Get arguments description string.
  std::string GetArgsHelpString() const;

 private:
  po::options_description opts_;
  bool is_help_ = false;
  std::string import_priv_key_;
  std::string import_pub_key_;
  std::string signing_file_;
  std::string verifying_file_;
  std::string signature_;
};

#endif
