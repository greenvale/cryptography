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

// **************************************************************************************************************
//   MATHEMTATICAL FUNCTIONS
// **************************************************************************************************************

template <typename T>
T modulo(T x, const uint32_t& n)
{
    while (x < 0)
        x += n;
    return x % n;
}

// **************************************************************************************************************
//   BITWISE FUNCTIONS
// **************************************************************************************************************

// circular left shift
template <typename T>
T circ_left_shift(const T& word,  const uint32_t& n)
{
    return (word << modulo(n,sizeof(T)*8)) | (word >> (sizeof(T)*8 - modulo(n,sizeof(T)*8)));
}

// circular right shift
template <typename T>
T circ_right_shift(const T& word, const uint32_t& n)
{
    return (word >> modulo(n,sizeof(T)*8)) | (word << (sizeof(T)*8 - modulo(n,sizeof(T)*8)));
}

// set/clear bit
template <typename T, bool big_endian>
void set_bit(T& word, const uint32_t& index, const bool& val)
{
    if (big_endian == false)
    {
        // little endian
        if (val == 1)
            word |= (T)1 << index;
        else
            word &= ~((T)1 << index);
    }
    else
    {
        // big endian
        if (val == 1)
            word |= (T)1 << (sizeof(T)*8 - 1 - index);
        else
            word &= ~((T)1 << (sizeof(T)*8 - 1 - index));
    }
}

// check bit
template <typename T, bool big_endian>
bool check_bit(T& word, const uint32_t& index)
{
    if (big_endian == false)
    {
        return (bool)((word >> index) & (T)1);
    }
    else
    {
        return (bool)((word >> (sizeof(T)*8 - 1 - index)) & (T)1);
    }
}

// toggle bit
template <typename T, bool big_endian>
void toggle_bit(T& word, const uint32_t& index)
{
    if (big_endian == false)
    {
        word ^= (T)1 << index;
    }
    else
    {
        word ^= (T)1 << (sizeof(T)*8 - 1 - index);
    }
}

// reverses bits in a datatype of any number of bytes
template <typename T>
T reverse_b(T x)
{
    T y = 0;
    for (int i = 0; i < sizeof(T)*8; ++i)
    {
        y = y << 1;
        y = y | (x & (T)1);
        x = x >> 1;
    }
    return y;
}

// keeps byte order the same
// reverses bit order within each byte
template <typename T>
T reverse_binB(const T& x)
{
    T y = 0;
    T k = (T)0xff << (sizeof(T) - 1)*8;
    T b;
    for (int i = 0; i < sizeof(T); ++i)
    {
        b = k & x;
        b = b >> (sizeof(T) - 1 - i)*8;
        y = y << 8;
        y = y | (T)gv::reverse_b((uint8_t)b);
        k = k >> 8;
    }
    return y;
}

// reverses order of bytes
// keeps bit order the same within each byte
template <typename T>
T reverse_B(T x)
{
    T y = 0;
    for (int i = 0; i < sizeof(T); ++i)
    {
        y = y << 8;
        y = y | (T)(x & (T)0xff);
        x = x >> 8;
    }
    return y;
}

// **************************************************************************************************************
//   HEXIDECIMAL 
// **************************************************************************************************************

// returns 32-bit word as hexcode string
template <typename T>
std::string to_hexcode(T word)
{
    std::string hexcode = "";

    // initialise kernel to isolate right-most 4 binary digits of word
    // this corresponds to a hexidecimal char
    T kernel = 0xf;

    // there are 2 hexi units per 1 byte
    for (int i = 0; i < sizeof(T) * 2; ++i)
    {   
        uint8_t conv = kernel & word;
        uint8_t hexcode_char;

        if (conv < 10)
            hexcode_char = 48 + conv;
        else
            hexcode_char = 97 + (conv - 10);

        hexcode = (char)hexcode_char + hexcode;
        word = word >> 4;
    }

    return hexcode;
}

// converts a hexcode string into a word of type T
template <typename T>
T from_hexcode(const std::string& hexcode)
{
    // each char in hexcode represents 4 bits so each byte contains 2 hex digits
    // therefore the size of the hexcode should be <= 2 * sizeof(T)
    assert(hexcode.size() <= 2*sizeof(T));

    T word = 0;

    for (int i = 0; i < hexcode.size(); ++i)
    {
        uint8_t hexcode_char = hexcode[i];

        // assert that this char is either 0,1,...,0 or a,b,...,e
        assert((hexcode_char >= 48 && hexcode_char <= 57) || (hexcode_char >= 97 && hexcode_char <= 102));

        word = word << 4;

        if (hexcode_char <= 57)
            word += (T)hexcode_char - 48;
        else
            word += (T)hexcode_char + 10 - 97;
    }

    return word;
}

// **************************************************************************************************************
//   PRINTING FUNCTIONS
// **************************************************************************************************************

// printed vector of words with char-wise breakdown within each word
// each char's binary, char and hex codes are printed
// integer datatype size is left as template parameter, e.g. uint32_t, uint64_t are likely candidates
template <typename T>
void print_words(const std::vector<T>& vec)
{
    // the size of vector should be limited to (2^64)-1
    uint64_t num_words = vec.size();

    for (int i = 0; i < num_words; ++i)
    {
        std::cout << "\nWORD " << i << "\nFull word (bin): \t" << std::bitset<32>(vec[i]) << std::endl;
        std::cout << "Full word (hex): \t" << to_hexcode<T>(vec[i]) << "\n" << std::endl;

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
            std::cout << "\t" << to_hexcode<char>((char)conv_8bit) << std::endl;
        }
    }
    std::cout << "\n" << std::endl;
}

} // namespace gv