#include <iostream>
#include "sha1.hpp"

int main(int argc, char* argv[]) {
    if (argc > 1) {

        std::string input(argv[1]);

        std::cout << input << " >>>> SHA1 >>>> " << gv::sha1::digest(input) << std::endl;

    }
}