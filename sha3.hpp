#pragma once

// SHA-3

#include <iostream>
#include <string>
#include <bitset>
#include <assert.h>
#include <cstring>
#include <algorithm>
#include <exception>

#include "crypto_useful.hpp"

/*

*/

// print message in sha3-style hexcode
// the data is little endian style but the byte order
// is flipped to read from left to right
// the hexcode for each byte is then calculated
template <typename T>
std::string sha3_hex(const std::vector<T>& x)
{
    std::string H;
    for (int i = 0; i < x.size(); ++i)
    {
        // reverse byte order to mimic text layout
        // bits within each byte are stored in little-endian style
        T rev = gv::reverse_B(x[i]);
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

// round constant function
uint64_t RC(const int& i)
{
    uint64_t rc = 0;
    return rc;
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
    N[0]            = gv::reverse_b((uint8_t)0b01100000);
    N[lenP/8 - 1]   = gv::reverse_b((uint8_t)0b00000001);

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

    // declare some variables
    std::vector<uint64_t> buf, buf2;
    int x, y, tmp; 

    std::vector<uint64_t> state(25, 0);

    // create the only block required, has size = r bits
    // store in 17 * 64-bit words
    std::vector<uint64_t> block0(r/(sizeof(uint64_t)*8));
    std::copy(N_64.begin(), N_64.begin() + r/(sizeof(uint64_t)*8), block0.begin());
    
    // ABSORBING
    std::cout << "~~~~ ABSORBING ~~~~" << std::endl;

    // copy 17*64-bit word block into state
    buf = std::vector<uint64_t>(25, 0);
    std::copy(block0.begin(), block0.end(), buf.begin());

    // state XOR (P0 || 0^c)
    std::transform(buf.cbegin(), buf.cend(), state.cbegin(), state.begin(),
        [](uint64_t x0, uint64_t x1){return x0 ^ x1;});

    // print initial state
/* */
    std::cout << "\n\n Initial state:\n";
    sha3_print_hex_grid(state);


    // perform KECCAK function on state
    // iterate rounds
    for (int i = 0; i < 12+2*l; ++i)
    {
        std::cout << "\n\n ~~~~ ROUND " << i << std::endl;

        // theta
        buf = std::vector<uint64_t>(5);
        buf2 = std::vector<uint64_t>(5);
        for (x = 0; x < 5; ++x)
            buf[x] = state[5*0+x]^state[5*1+x]^state[5*2+x]^state[5*3+x]^state[5*4+x];
        for (x = 0; x < 5; ++x)
            buf2[x] = buf[gv::modulo(x-1, 5)] ^ gv::circ_left_shift(buf[gv::modulo(x+1, 5)], 1);
        for (x = 0; x < 5; ++x)
            for (y = 0; y < 5; ++y)
                state[5*y + x] = state[5*y + x] ^ buf2[x];

        // print state after theta
/* */
        std::cout << "\n\nState after theta:\n";
        sha3_print_hex_grid(state);

        // rho
        x = 1; y = 0;
        buf = state;
        for (int t = 0; t <= 23; ++t)
        {
            state[5*y + x] = gv::circ_left_shift(buf[5*y + x], (t+1)*(t+2)/2);
            tmp = x;
            x = y;
            y = gv::modulo((2*tmp + 3*y), 5);
        }

        // print state after rho
/* */
        std::cout << "\n\nState after rho:\n";
        sha3_print_hex_grid(state);

        // pi
        buf = state;
        for (x = 0; x < 5; ++x)
            for (y = 0; y < 5; ++y)
                state[5*y + x] = buf[5*x + gv::modulo(x+3*y, 5)];

        // print state after pi
/* */
        std::cout << "\n\nState after pi:\n";
        sha3_print_hex_grid(state);

        // chi
        buf = state;
        for (x = 0; x < 5; ++x) {
            for (y = 0; y < 5; ++y) {
                state[5*y + x] = buf[5*y + x] ^ 
                    ((buf[5*y + gv::modulo(x+1,5)] ^ ~((uint64_t)0)) & buf[5*y + gv::modulo(x+2,5)]);
            }
        }
        // print state after chi
/* */
        std::cout << "\n\nState after chi:\n";
        sha3_print_hex_grid(state);

        // iota
        uint64_t rc = 0;
        for (int j = 0; j <= l; ++j)
        {
            int m = gv::modulo(j + 7*i, 255);
            if (m != 0)
            {
                uint64_t R = 1;
                for (int k = 0; k < m; ++k)
                {
                    R = R << 1;
                    bool r8 = gv::check_bit<uint64_t,0>(R, 8);
                    gv::set_bit<uint64_t,0>(R, 0, gv::check_bit<uint64_t,0>(R, 0) ^ r8);
                    gv::set_bit<uint64_t,0>(R, 4, gv::check_bit<uint64_t,0>(R, 4) ^ r8);
                    gv::set_bit<uint64_t,0>(R, 5, gv::check_bit<uint64_t,0>(R, 5) ^ r8);
                    gv::set_bit<uint64_t,0>(R, 6, gv::check_bit<uint64_t,0>(R, 6) ^ r8);
                    R = R & (uint64_t)0xff;
                }
                gv::set_bit<uint64_t,0>(rc, (1<<j)-1, gv::check_bit<uint64_t,0>(R, 0));
            }
            else
                gv::set_bit<uint64_t,0>(rc, (1<<j)-1, 1);
        }
        std::cout << "Round constant: " << sha3_hex(std::vector<uint64_t>({rc})) << std::endl;
        state[5*0 + 0] = state[5*0 + 0] ^ rc;
    
    // print state after iota
/* */
        std::cout << "\n\nState after iota:\n";
        sha3_print_hex_grid(state);
    
    }

    // SQUEEZING
    std::cout << "~~~~ SQUEEZING ~~~~" << std::endl;

    // need to get message of length trunc d (d = 256-bits, rate = 1088 bits)
}