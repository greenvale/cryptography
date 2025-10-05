#include <iostream>
#include "sha3_256.hpp"

int main(int argc, char* argv[]) {
    // if a string input is provided, argc >= 2. The first element of argv is the executable name
    // the second element of the array is the desired input. We take the first complete string without spaces.
    if (argc > 1) {
        std::cout << argv[1] << " >>>> SHA3-256 >>>> " << gv::sha3_256::digest(std::string(argv[1])) << std::endl;
    }
}