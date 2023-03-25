#pragma once
/*
    SHA-3 256 Algorithm

    - Outputs 256-bit message digest

    - Takes input of string of bytes (does not handle general string of bits)

    - Parameters:
        l = 6
        w = 2^l = 64            (lane size in bits)
        b = 25*w = 1600         (width in bits)
        d = 256                 (msg digest size)
        c = 2*d = 512           (capacity in bits)
        r = b - c = 1088        (rate in bits)

        block size = r
        in bytes = 1088/8 = 136
        in 64-bit vals = 136/8 = 17

*/

#include <iostream>
#include <string>
#include <bitset>
#include <assert.h>
#include <cstring>
#include <algorithm>
#include <exception>

#include "crypto_useful.hpp"

namespace gv
{

namespace sha3_256
{

//********************************************************************************************************************

// FUNCTION DECLARATIONS

// step mappings
std::vector<uint64_t> theta(const std::vector<uint64_t>& state);
std::vector<uint64_t> pi(const std::vector<uint64_t>& state);
std::vector<uint64_t> rho(const std::vector<uint64_t>& state);
std::vector<uint64_t> chi(const std::vector<uint64_t>& state);
std::vector<uint64_t> iota(const int& i, const std::vector<uint64_t>& state);
uint64_t RC(const int& i);

// main digest fcn
std::string digest(const std::string& str);

// hexcode fcns
template <typename T>
std::string hex(const std::vector<T>& x);
template <typename T>
void print_hex_grid(std::vector<T>& x);

//********************************************************************************************************************

// message digest
std::string digest(const std::string& str)
{
    // PADDING

    int width = 1600;
    int capacity = 2*256;
    int rate = width - capacity;        // 1088

    // obtain vector of chars from input string
    int num_chars = str.size();
    std::vector<uint8_t> msg(str.c_str(), str.c_str() + str.size());

    // the string of bits reads from left to right and is indexed from left to right (i.e. big-endian)
    // however, this code does bitwise operations from right to left (i.e. little-endian)
    // therefore, the bits in each byte in the input string must be reversed
    std::transform(msg.cbegin(), msg.cend(), msg.begin(), [](uint8_t x){return gv::reverse_b<uint8_t>(x);});

    // the message will be divided into blocks of 1088 bits (= rate)
    // a suffix of 01 is applied meaning 1 byte will be appended to the input string
    // a padding rule of 10*1 is applied

    // calculate number of extra bytes
    int extra_bytes = gv::modulo(-num_chars - 1, rate/8);

    // extend msg vector of bytes to contain extra bytes
    msg.insert(msg.cend(), extra_bytes + 1, 0);

    std::cout << "Extra bytes needed: " << (extra_bytes + 1) << " | Number of bytes in padded message: " << msg.size() << std::endl;

    // add padding to message
    if (extra_bytes == 0)
    {
        // only 1 byte needs to be added; this byte is: 
        // 0110 0001 (big endian)
        // 1000 0110 (little endian)
        // 8    6    (little endian hexcode)
        *(msg.end() - 1) = reverse_b<uint8_t>(0b01100001);
    }
    else
    {
        // two bytes need to be added; these bytes are
        // 0110 0000 || ... || 0000 0001 (big endian)
        // 0000 0110 || ... || 1000 0000
        // 0    6    || ... || 8    0
        msg[num_chars] = reverse_b<uint8_t>(0b01100000);
        *(msg.end() - 1) = reverse_b<uint8_t>(0b00000001);
    }

    // copy message into vector 64-bit words
    assert((num_chars + 1 + extra_bytes) % 8 == 0);
    std::vector<uint64_t> padmsg((uint64_t*)msg.data(), (uint64_t*)(msg.data()) + (num_chars + 1 + extra_bytes)/8);

    print_hex_grid(padmsg);

    // divide padded message into blocks of 17 * 64-bit words
    std::vector<std::vector<uint64_t>> blocks;
    assert(padmsg.size() % 17 == 0);
    for (int i = 0; i < padmsg.size() / 17; ++i)
        blocks.push_back(std::vector<uint64_t>(padmsg.cbegin() + i*17, padmsg.cbegin() + (i+1)*17));

    // *****************************************************

    // SPONGE FUNCTION

    // initialise state as zeros
    std::vector<uint64_t> state(25, 0);

    // iterate through blocks and absorb them
    for (int n = 0; n < blocks.size(); ++n)
    {
        // copy 17*64-bit word block into state
        std::vector<uint64_t> buf(25, 0);
        std::copy(blocks[n].begin(), blocks[n].end(), buf.begin());

        // calculate state XOR (P0 || 0^c) (buf) and write into state
        std::transform(buf.cbegin(), buf.cend(), state.cbegin(), state.begin(),
            [](uint64_t x0, uint64_t x1){return x0 ^ x1;});

        std::cout << "\n\n Initial state:\n"; print_hex_grid(state);

        // perform KECCAK function on state
        // iterate rounds (number of rounds = 12+2*l, l = 6)
        for (int i = 0; i < 12+2*6; ++i)
        {
            std::cout << "\n\n ~~~~ ROUND " << i << std::endl;
            
            // theta
            state = theta(state);           std::cout << "\n\nState after theta:\n";    print_hex_grid(state);

            // rho
            state = rho(state);             std::cout << "\n\nState after rho:\n";      print_hex_grid(state);

            // pi
            state = pi(state);              std::cout << "\n\nState after pi:\n";       print_hex_grid(state);

            // chi
            state = chi(state);             std::cout << "\n\nState after chi:\n";      print_hex_grid(state);

            // iota
            state = iota(i, state);         std::cout << "\n\nState after iota:\n";     print_hex_grid(state);
        
        }
    }
    
    return "";
}

// theta step mapping
std::vector<uint64_t> theta(const std::vector<uint64_t>& state)
{
    std::vector<uint64_t> buf(5);
    std::vector<uint64_t> buf2(5);
    std::vector<uint64_t> new_state(25);
    for (int x = 0; x < 5; ++x)
        buf[x] = state[5*0+x] ^ state[5*1+x] ^ state[5*2+x] ^ state[5*3+x] ^ state[5*4+x];
    for (int x = 0; x < 5; ++x)
        buf2[x] = buf[gv::modulo(x-1, 5)] ^ gv::circ_left_shift(buf[gv::modulo(x+1, 5)], 1);
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y)
            new_state[5*y + x] = state[5*y + x] ^ buf2[x];
    return new_state;
}

// rho step mapping
std::vector<uint64_t> rho(const std::vector<uint64_t>& state)
{
    std::vector<uint64_t> new_state = state;
    int x = 1; 
    int y = 0;
    int tmp;
    for (int t = 0; t <= 23; ++t)
    {
        new_state[5*y + x] = gv::circ_left_shift(state[5*y + x], (t+1)*(t+2)/2);
        tmp = x;
        x = y;
        y = gv::modulo((2*tmp + 3*y), 5);
    }
    return new_state;
}

// pi step mapping
std::vector<uint64_t> pi(const std::vector<uint64_t>& state)
{
    std::vector<uint64_t> new_state(25);
    for (int x = 0; x < 5; ++x)
        for (int y = 0; y < 5; ++y)
            new_state[5*y + x] = state[5*x + gv::modulo(x+3*y, 5)];
    return new_state;
}

// chi step mapping
std::vector<uint64_t> chi(const std::vector<uint64_t>& state)
{
    std::vector<uint64_t> new_state(25);
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            new_state[5*y + x] = state[5*y + x] ^ 
                ((state[5*y + gv::modulo(x+1,5)] ^ ~((uint64_t)0)) & state[5*y + gv::modulo(x+2,5)]);
        }
    }
    return new_state;
}

// iota step mapping
std::vector<uint64_t> iota(const int& i, const std::vector<uint64_t>& state)
{
    uint64_t rc = RC(i);
    std::vector<uint64_t> new_state = state;
    new_state[5*0 + 0] = new_state[5*0 + 0] ^ rc;
    return new_state;
}

// round constant function
uint64_t RC(const int& i)
{
    uint64_t rc = 0;
    for (int j = 0; j <= 6; ++j)
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
    return rc;
}

// print message in sha3-style hexcode
// the data is little endian style but the byte order
// is flipped to read from left to right
// the hexcode for each byte is then calculated
template <typename T>
std::string hex(const std::vector<T>& x)
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
void print_hex_grid(std::vector<T>& x)
{
    std::string Htab;
    std::string H = hex(x);
    for (int i = 0; i < H.size()/2; ++i)
    {
        if (i % 16 == 0 && i > 0)
            Htab += "\n";
        Htab += H.substr(2*i, 2);
        Htab += " ";
    }
    std::cout << Htab << std::endl;
}

} // namespace sha3_256

} // namespace gv