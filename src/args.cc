#include "args.h"

#include <sstream>

Args::Args(int argc, const char *argv[]) {
  opts_.add_options()
    ("help,h", "Show help document.")
    ("generate,g", "Request to generate new key pair.")
    ("import_priv_key,p", po::value(&import_priv_key_), "Import private key.")
    ("import_pub_key,u", po::value(&import_pub_key_), "Import public key.")
    ("siging_file,s", po::value(&signing_file_), "Signing file.")
    ("verifying_file,v", po::value(&verifying_file_), "Verifying file.")
    ("signature,i", po::value(&signature_), "Signature.")
    ;

  po::variables_map vars;
  po::store(po::parse_command_line(argc, argv, opts_), vars);
  po::notify(vars);

  if (vars.count("help") > 0) {
    is_help_ = true;
  }

  if (vars.count("generate") > 0) {
    is_generate_new_key_ = true;
  }
}

std::string Args::GetArgsHelpString() const {
  std::stringstream ss;
  ss << opts_;
  return ss.str();
}
