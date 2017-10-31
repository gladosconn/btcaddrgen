#include "args.h"

#include <sstream>

Args::Args(int argc, const char *argv[]) {
    opts_.add_options()
        ("help", "Show help document.")
        ;

    po::variables_map vars;
    po::store(po::parse_command_line(argc, argv, opts_), vars);
    po::notify(vars);

    if (vars.count("help") > 0) {
        is_help_ = true;
    }
}

std::string Args::GetArgsHelpString() const {
    std::stringstream ss;
    ss << opts_;
    return ss.str();
}
