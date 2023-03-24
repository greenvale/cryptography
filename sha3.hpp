#pragma once

// SHA-3

#include <iostream>
#include <string>
#include <bitset>
#include <assert.h>
#include <cstring>
#include <algorithm>

#include "crypto_useful.hpp"

/*
    NOTES FROM NIST FIPS 202 SPECIFICATION:
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Overview
    ~~~~~~~~

    Takes message as a bit string.
    Returns message digest of certain length, e.g. SHA-256 returns 256-bit digest.

    The permutation used is a member of a family of permutations called KECCAK-p.

    2-bit suffix is appended to message to distinguish SHA-3 from SHA-3 XOFs (extendable output fcn).

    Glossary
    ~~~~~~~~

    multi-rate padding      =       padding rule pad10*1, i.e. 10000.....00001

    round                   =       sequence of step-mappings, i.e. theta, pi, ...

    round constant          =       for each round of a permutation, a lane value that is determined by round index

    
    M               =       input string into SHA-3 hash fcn
    N               =       input string into sponge fcn

    c               =       capacity of sponge function (width of underlying fcn minus the rate)
    r               =       rate
    d               =       utput length in bits
    w               =       lane size
    l               =       log2 of lane size, i.e. 2^l == w
    nr              =       number of rounds = 12 + 2l
    b               =       width of permutation in bits == 25*w 

    r + c           =       b

    X[i]            =       i'th bit of bit string X. Indices increase from left to right,
                            e.g. X = 101000 -> X[2] = 1

    Trunc_s(X)      =       The string comprised of X[0] - X[s-1], e.g. Trunc_2(10100) = 10
    X || Y          =       Concatenation of 2 strings X and Y, e.g. 1011||0110 = 10110110
    m mod n         =       Integer r, 0 <= r < n s.t. m-r = kn for some integer k
                            e.g. 11 mod 5 = 1, -11 mod 5 = 4

    Permutations
    ~~~~~~~~~~~~

    Permutations depend on fixed length of strings that are permuted (width, b)
    and number of iterations of internal transform (round) (nr).


    For this implementation we use l = 6 -> w = 2^6 = 64 -> b = 25*64 = 1600

    State is arranged in 25 lanes, i.e. Lane (0,0) || ... || Lane(4,0) || Lane(0,1) || ... || Lane(4,4)

*/

// reverses bits in a datatype of any number of bytes
template <typename T>
T reverse(T x)
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
T reverse_bitorder(const T& x)
{
    T y = 0;
    T k = (T)0xff << (sizeof(T) - 1)*8;
    T b;
    for (int i = 0; i < sizeof(T); ++i)
    {
        b = k & x;
        b = b >> (sizeof(T) - 1 - i)*8;
        y = y << 8;
        y = y | (T)reverse((uint8_t)b);
        k = k >> 8;
    }
    return y;
}

// reverses order of bytes
// keeps bit order the same within each byte
template <typename T>
T reverse_byteorder(T x)
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

// print message in sha3-style hexcode
template <typename T>
std::string sha3_hex(const std::vector<T>& x)
{
    std::string H;
    std::string buf;

    for (int i = 0; i < x.size(); ++i)
    {
        // reverse byte order to mimic text layout
        // bits within each byte are stored in little-endian style
        T rev = reverse_byteorder(x[i]);
        H += gv::to_hexcode(rev);
    }
    
    return H;
}

// prints message in grid style as shown in example document
template <typename T>
void sha3_print_hex_grid(std::vector<T>& x)
{
    std::string Htab;
    std::string H = sha3_hex(x);
    for (int i = 0; i < H.size()/2; ++i)
    {
        if (i % 16 == 0 && i > 0)
            Htab += "\n";
        Htab += H.substr(2*i, 2);
        Htab += " ";
    }
    std::cout << Htab << std::endl;
}

// empty message
void sha3_256()
{
    uint32_t l = 6;
    uint32_t w = 1<<l;  // lane size (in bits)
    uint32_t b = 25*w;  // width (in bits)
    uint32_t d = 256;   // msg digest len (in bits)
    uint32_t c = 2*d;   // capacity (in bits)
    uint32_t r = b - c; // rate (in bits)

    uint32_t lenP = r; // length of padded msg in bits

    std::cout << "Rate (r): " << r << std::endl;
    std::cout << "Number of bits in padded msg (lenP): " << lenP << std::endl;
    std::cout << "Number of blocks (lenP/r): " << lenP / r << std::endl;
    std::cout << "lenP % r == 0 : check -> " << lenP % r << std::endl;
    std::cout << "Block size (lanes): " << r / (8 * sizeof(uint64_t)) << std::endl;

    // create padded empty message as vector of bytes
    // first byte is __ (nothing) appended by 01, then 1 to start padding
    // this is reversed s.t. 0th index is on RHS to give correct numerical value
    // final byte in padded message is 00..001, which is also reversed.
    std::vector<uint8_t> N(200, 0);
    N[0]            = reverse((uint8_t)0b01100000);
    N[lenP/8 - 1]   = reverse((uint8_t)0b00000001);

    // convert padded message into vector of 64-bit words
    // to be divided into blocks of size 17
    std::vector<uint64_t> N_64((uint64_t*)N.data(), (uint64_t*)(N.data()) + 25);

    // print padded message in hexcode grid
/* */
    //std::cout << sha3_hex(N) << std::endl;
    //std::cout << sha3_hex(N_64) << std::endl;

    std::cout << "\nPadded message:" << std::endl;
    sha3_print_hex_grid(N_64);

    // print padded message in binary
/* 
    //for (auto n : N)
    //    std::cout << std::bitset<8>(n) << std::endl;
    std::cout << "\n\n";
    for (auto n : N_64)
        std::cout << std::bitset<64>(n) << std::endl;
*/
    // each block is 136 bytes == 17 * 64-bit lanes

    std::vector<uint64_t> buf;
    std::vector<uint64_t> state(25, 0);

    // create the only block required, has size = r bits
    // store in 17 * 64-bit words
    std::vector<uint64_t> block0(r/(sizeof(uint64_t)*8));
    std::copy(N_64.begin(), N_64.begin() + r/(sizeof(uint64_t)*8), block0.begin());
    
    // ABSORBING

    // copy 17*64-bit word block into state
    buf = std::vector<uint64_t>(25, 0);
    std::copy(block0.begin(), block0.end(), buf.begin());

    // state XOR (P0 || 0^c)
    // use transform

    // print initial state
/*
    std::cout << "\n\n Initial state:\n";
    sha3_print_hex_grid(state);
*/

    // perform KECCAK function on state
    // iterate rounds
        // calculate round index ir
        // theta
        // rho
        // pi
        // chi
        // iota

    // SQUEEZING

    // need to get message of length trunc d (d = 256-bits, rate = 1088 bits)
}