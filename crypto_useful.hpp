/* 
Useful functions for cryptology/cryptography

William Denny

*/

#pragma once

#include <iostream>
#include <vector>
#include <tuple>
#include <string>
#include <bitset>
#include <array>
#include <assert.h>

namespace gv
{

// circular left shift bitwise operation for int of datatype T
// likely candidates are uint32_t, uint64_t
// takes uint32_t n and T x as parameters, where n is the number of left rotations and x is var to be shifted
// returns the shifted x
template <typename T>
T circ_left_shift(const uint32_t& n, const T& x)
{
    return ((x << n) | (x >> (sizeof(T)*8 - n)));
}

// **************************************************************************************************************

// returns 32-bit word as hex string
// makes copy of word as it is modified by code
template <typename T>
std::string word_to_hex(T word)
{
    std::string hex = "";

    // initialise kernel to isolate right-most 4 binary digits of word
    // this corresponds to a hexidecimal char
    T kernel = 0xf;

    // there are 2 hexi units per 1 byte
    for (int i = 0; i < sizeof(T) * 2; ++i)
    {   
        uint8_t conv = kernel & word;
        uint8_t hex_char;

        if (conv < 10)
            hex_char = 48 + conv;
        else
            hex_char = 97 + (conv - 10);

        hex = (char)hex_char + hex;
        word = word >> 4;
    }

    return hex;
}

// **************************************************************************************************************

// converts a hex string into a word of type T, given by template parameter
// likely candidates are uint32_t, uint64_t
// letters must be in lower case!
template <typename T>
T hex_to_word(const std::string& hex)
{
    // each char in hexcode represents 4 bits
    // therefore the size of the hexcode should be <= 2 * sizeof(T)
    assert(hex.size() <= 2*sizeof(T));

    T word = 0;

    for (int i = 0; i < hex.size(); ++i)
    {
        uint8_t hex_char = hex[i];

        // assert that this char is either 0,1,...,0 or a,b,...,e
        assert((hex_char >= 48 && hex_char <= 57) || (hex_char >= 97 && hex_char <= 102));

        word = word << 4;

        if (hex_char <= 57)
            word += (T)hex_char - 48;
        else
            word += (T)hex_char + 10 - 97;
    }

    return word;
}

// **************************************************************************************************************

// printed vector of words with char-wise breakdown within each word
// each char's binary, char and hex codes are printed
// integer datatype size is left as template parameter, e.g. uint32_t, uint64_t are likely candidates
template <typename T>
void print_word_vec(const std::vector<T>& vec)
{
    // the size of vector should be limited to (2^64)-1
    uint64_t num_words = vec.size();

    for (int i = 0; i < num_words; ++i)
    {
        std::cout << "\nWORD " << i << "\nFull word (bin): \t" << std::bitset<32>(vec[i]) << std::endl;
        std::cout << "Full word (hex): \t" << word_to_hex(vec[i]) << "\n" << std::endl;

        // each char represents 1 byte (8 bits)
        // therefore the number of chars = sizeof(T)
        for (int j = 0; j < sizeof(T); ++j)
        {
            // create a kernel for isolating jth char in word
            T kernel = 0xff;
            kernel = kernel << (sizeof(T) - 1 - j) * 8;

            // get convolution of kernel with word
            T conv = vec[i] & kernel;

            // get last 8 significant bits of convolution
            // store in 8 bit int variable
            uint8_t conv_8bit = conv >> (sizeof(T) - 1 - j) * 8;

            // get binary representation of char
            std::bitset<8> char_bin(conv_8bit);

            std::cout << "Char [" << j << "] \t ";
            std::cout << char_bin << " \t ";
            
            // display character (depending on character)
            if (conv_8bit >= 33)
                std::cout << (char)conv_8bit;
            else if (conv_8bit < 33) // command chars
            {
            }

            // display hexcode
            std::cout << "\t" << word_to_hex((char)conv_8bit) << std::endl;
        }
    }
    std::cout << "\n" << std::endl;
}

} // namespace gv