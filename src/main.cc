#include <iostream>
#include <boost/program_options.hpp>

#include "args.h"

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
    return 0;
}