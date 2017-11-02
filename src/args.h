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

  /// Get arguments description string.
  std::string GetArgsHelpString() const;

 private:
  po::options_description opts_;
  bool is_help_ = false;
};

#endif
