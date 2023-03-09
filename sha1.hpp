/* 
SHA (security hashing algorithm) functions/classes
- SHA-1

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

#include "useful.hpp"

namespace gv
{

// **************************************************************************************************************
// SHA-1
// **************************************************************************************************************

// SHA-1 algorithm parameters/datatypes

uint32_t sha_1_block_size = 512;

using sha_1_word = uint32_t;

using sha_1_len = uint64_t;

// **************************************************************************************************************

class sha_1
{

public:
    sha_1() = delete;

    static std::vector<sha_1_word> msg_digest(const std::string& str);

private:
    static std::vector<sha_1_word> preprocess_str(const std::string& str);

    static sha_1_word f(const uint32_t& t, const sha_1_word& B, const sha_1_word& C, const sha_1_word& D);
    static sha_1_word K(const uint32_t& t);

};

// preprocesses a string into array of words with padding
// input str must have num_bits < 2^64 otherwise this function will not work properly
// returns a vector containing words
std::vector<sha_1_word> sha_1::preprocess_str(const std::string& str)
{
    // compute number of bits and chars in string provided
    sha_1_len num_str_chars = str.size();
    sha_1_len num_str_bits = num_str_chars * sizeof(char) * 8;

    // compute number of words required to store all of the chars of the string
    // each word takes up to sizeof(word) * 8 bits
    sha_1_len num_str_words;
    if (num_str_bits % (sizeof(sha_1_word) * 8) == 0)
    {
        num_str_words = num_str_bits / (sizeof(sha_1_word) * 8);
    }
    else
    {
        // need upper bound of num words, / operation rounds down so add 1
        num_str_words = 1 + (num_str_bits / (sizeof(sha_1_word) * 8));
    }

    // compute number of zeros in padding
    // by taking difference between block_size and overflow of bits from previous block of str + padding elements
    sha_1_len num_zero_bits = sha_1_block_size - ((num_str_bits + 1 + (sizeof(sha_1_len) * 8)) % sha_1_block_size);

    // calculate total number of bits (should be positive, integer multiple of block_size)
    sha_1_len num_padded_str_bits = num_str_bits + 1 + num_zero_bits + (sizeof(sha_1_len) * 8);

    // initialise vector for storing words, set all words to zero prior to assigning chars
    sha_1_len num_padded_str_words = num_padded_str_bits / (sizeof(sha_1_word) * 8);
    std::vector<uint32_t> word_vec(num_padded_str_words, 0);

    // track starting point for padding
    sha_1_len pad_begin_word, pad_begin_char;

    // iterate through each word available for storing characters
    for (int i = 0; i < num_str_words; ++i)
    {
        // iterate through each char storage point in the word
        // the number of chars in each word == sizeof(word)
        for (int j = 0; j < sizeof(sha_1_word); ++j)
        {
            // check that there are still characters left to add
            if ((sizeof(sha_1_word)*i) + j < num_str_chars)
            {
                word_vec[i] = word_vec[i] << 8;
                word_vec[i] += (sha_1_word)str[(sizeof(sha_1_word)*i) + j];
            }
            else
            {
                // no more characters to add but final word not fully used
                // therefore start point for padding is this char in the final word
                pad_begin_word = i;
                pad_begin_char = j;

                // words are aligned to the left, therefore push final chars to the left
                word_vec[i] = word_vec[i] << (sizeof(sha_1_word) - j) * 8;

                break;
            }
        }
    }

    // if words are fully used up by then padding starts at next word, 0th char
    if (num_str_bits % (sizeof(sha_1_word) * 8) == 0)
    {
        pad_begin_word = num_str_words;
        pad_begin_char = 0;
    }

    // add binary 1 in pos 7 of start_char to indicate start of padding
    sha_1_word one = 0b10000000;
    one = one << (sizeof(sha_1_word) - 1 - pad_begin_char) * 8;
    word_vec[pad_begin_word] += one;

    // encode the length of the string into the designated words
    uint32_t num_strlen_words = sizeof(sha_1_len) / sizeof(sha_1_word);
    
    for (int i = 0; i < num_strlen_words; ++i)
    {
        sha_1_len kernel = ((sha_1_len)1 << (sizeof(sha_1_word) * 8)) - 1;
        kernel = kernel << (num_strlen_words - 1 - i) * (sizeof(sha_1_word) * 8);
        sha_1_len conv = kernel & num_str_bits;
        sha_1_word conv_word = conv >> (num_strlen_words - 1 - i) * (sizeof(sha_1_word) * 8);
        word_vec[num_padded_str_words - num_strlen_words + i] = conv_word;
    }

    return word_vec;
}

// logical function, taking t parameter 0 <= t < 80
sha_1_word sha_1::f(const uint32_t& t, const sha_1_word& B, const sha_1_word& C, const sha_1_word& D)
{
    assert(t >= 0 && t < 80);

    if (t >= 0 && t < 20)
        return (B & C) | ((~B) & D);
    
    else if ((t >= 20 && t < 40) || (t >= 60 && t < 80))
        return B ^ C ^ D;
    
    else if (t >= 40 && t < 60)
        return (B & C) | (B & D) | (C & D);

    else
        return 0;
}

// constant function, taking t parameter 0 <= t < 80
sha_1_word sha_1::K(const sha_1_word& t)
{
    assert(t >= 0 && t < 80);

    if (t >= 0 && t < 20)
        return 0x5a827999;
    
    else if (t >= 20 && t < 40)
        return 0x6ed9eba1;
    
    else if (t >= 40 && t < 60)
        return 0x8f1bbcdc;

    else if (t >= 60 && t < 80)
        return 0xca62c1d6;

    else
        return 0;
}

// computes message digest using sha_1 algorithm
std::vector<sha_1_word> sha_1::msg_digest(const std::string& str)
{
    // ensures that string is properly padded
    std::vector<sha_1_word> word_vec = preprocess_str(str);

    print_word_vec(word_vec);

    // compute number of blocks provided
    // each block contains block_size / (sizeof(word) * 8) number of words
    uint32_t num_blocks = word_vec.size() / (sha_1_block_size / (sizeof(sha_1_word) * 8));

    // create buffer variables
    sha_1_word  A,  B,  C,  D,  E;
    sha_1_word H0, H1, H2, H3, H4;

    // temp buffer
    sha_1_word temp;

    // create word sequence
    std::array<sha_1_word, 80> word_seq;

    // before processing blocks, initialise H0, H1, H2, H3, H4 in buffer2
    H0 = 0x67452301;
    H1 = 0xefcdab89;
    H2 = 0x98badcfe;
    H3 = 0x10325476;
    H4 = 0xc3d2e1f0;

    // iterate through each 512-bit word block
    for (int i = 0; i < num_blocks; ++i)
    {
        // assign word_seq[0] - word_seq[15] as words in word block
        for (int j = 0; j < 16; ++j)
        {
            word_seq[j] = word_vec[i*16 + j];
        }

        // assign remaining words in word_seq according to formula
        for (int j = 16; j < 80; ++j)
        {
            word_seq[j] = circ_left_shift(1, word_seq[j - 3] ^ word_seq[j - 8] ^ word_seq[j - 14] ^ word_seq[j - 16]);
        }

        // initialise A, B, C, D, E in buffer1 to be H0, H1, H2, H3, H4 in buffer2
        A = H0;
        B = H1;
        C = H2;
        D = H3;
        E = H4;

        // main loop
        for (int j = 0; j < 80; ++j)
        {
            temp = circ_left_shift(5, A) + f(j, B, C, D) + E + word_seq[j] + K(j);
            
            E = D;
            D = C;
            C = circ_left_shift(30, B);
            B = A;
            A = temp;
        }

        // does this handle overflow and its undefined behaviour?
        H0 = H0 + A;
        H1 = H1 + B;
        H2 = H2 + C;
        H3 = H3 + D;
        H4 = H4 + E;
    }

    return {H0, H1, H2, H3, H4};
}

} // namespace gv