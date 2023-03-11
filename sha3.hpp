/* 
SHA (security hashing algorithm) functions/classes
- SHA-3

William Denny
9/3/23
*/

#pragma once

#include <iostream>
#include <string>
#include <bitset>
#include <assert.h>
#include <cstring>

#include "crypto_useful.hpp"

namespace gv
{

namespace sha3
{

// theta step mapping
template <typename lane>
void sha3_theta(lane* state)
{
    uint32_t w = sizeof(lane) * 8;

    // step 1
    lane* C = new lane[5];
    for (uint32_t x = 0; x < 5; ++x)
    {
        C[x] = state[5*0 + x];
        for (uint32_t y = 1; y < 5; ++y)
            C[x] = C[x] ^ state[5*y + x];
    }

    // step 2
    lane* D = new lane[5];
    for (uint32_t x = 0; x < 5; ++x)
    {
        D[x] = C[modulo(x-1, 5)] ^ circ_right_shift<lane>(C[(x+1) % 5], 1); 
    }

    // step 3
    for (uint32_t x = 0; x < 5; ++x)
    {
        for (uint32_t y = 0; y < 5; ++y)
        {
            state[5*y + x] = state[5*y + x] ^ D[x];
        }
    }

    delete[] C, D;
}

// rho step mapping
template <typename lane>
void sha3_rho(lane* state, lane* buffer)
{
    uint32_t w = sizeof(lane) * 8;

    // step 1
    buffer[5*0 + 0] = state[5*0 + 0];
    
    // step 2
    uint32_t x, y, temp;
    x = 1;
    y = 0;

    // step 3
    uint32_t right_shift;
    for (uint32_t t = 0; t <= 23; ++t)
    {
        right_shift = modulo((t+1) * (t+2) / 2, w);
        buffer[5*x + y] = circ_right_shift<lane>(state[5*x + y], right_shift);
        temp = x;
        x = y;
        y = modulo(2*temp + 3*y, 5);
    }

    // copy buffer data into state
    std::memcpy(state, buffer, 25 * sizeof(lane));
}

// pi step mapping
template <typename lane>
void sha3_pi(lane* state, lane* buffer)
{
    for (uint32_t x = 0; x < 5; ++x)
    {
        for (uint32_t y = 0; y < 5; ++y)
        {
            buffer[5*y + x] = state[5*x + modulo(x + 3*y, 5)];
        }
    }

    // copy buffer data into state
    std::memcpy(state, buffer, 25 * sizeof(lane));
}

// chi step mapping
template <typename lane>
void sha3_chi(lane* state)
{
    for (uint32_t x = 0; x < 5; ++x)
    {
        for (uint32_t y = 0; y < 5; ++y)
        {
            state[5*y + x] = state[5*y + x] ^ ((state[5*y + modulo((x+1), 5)] ^ 1) & state[5*y + modulo((x+2), 5)]);
        }
    }
}

// rc function for iota step mapping
// input t = j + 7*ir for j=0,...,l and ir=0,...,num_rnds-1
bool sha3_rc(const uint32_t& t)
{
    if (t % 255 == 0)
        return 1;

    uint16_t R = 1 << 15;
    for (uint32_t i = 1; i <= t % 255; ++i)
    {
        R = R >> 1;
        R &= 0b1111111110000000; // only keep digits 0 -> 8
        set_bit<uint16_t, true>(R, 0, (check_bit<uint16_t, true>(R, 0) ^ check_bit<uint16_t, true>(R, 8)));
        set_bit<uint16_t, true>(R, 4, (check_bit<uint16_t, true>(R, 4) ^ check_bit<uint16_t, true>(R, 8)));
        set_bit<uint16_t, true>(R, 5, (check_bit<uint16_t, true>(R, 5) ^ check_bit<uint16_t, true>(R, 8)));
        set_bit<uint16_t, true>(R, 6, (check_bit<uint16_t, true>(R, 6) ^ check_bit<uint16_t, true>(R, 8)));
    }
    return check_bit<uint16_t, true>(R, 0);
}

// iota step mapping
template <typename lane>
void sha3_iota(const uint32_t& l, lane* state, const uint32_t& round_index)
{
    assert((1<<l) == sizeof(lane)*8);

    // step 2
    lane RC = 0;

    // step 3
    for (uint32_t j = 0; j <= l; ++j)
        set_bit<lane, true>(RC, (1<<j) - 1, sha3_rc(j + 7*round_index));

    state[5*0 + 0] = state[5*0 + 0] ^ RC;
}

// keccak-p algorithm
template <typename lane>
void sha3_keccakp(const int32_t& l, const int32_t& num_rnds, lane* state, lane* buffer)
{   
    assert((1<<l) == sizeof(lane)*8);
    uint32_t ir;
    for (uint32_t i = 0; i < num_rnds; ++i)
    {
        ir = i + 12 + 2*l - num_rnds; // ranges from 12+2l-nr -> 12+2l-1
        sha3_theta<lane>(state);
        sha3_rho<lane>(state, buffer);
        sha3_pi<lane>(state, buffer);
        sha3_chi<lane>(state);
        sha3_iota<lane>(l, state, ir);
    }
}

// main algorithm
// d = digest length in bits (256)
// c = capacity in bits (512)
// l = 6 (w = 64 = 1<<6)
template <int32_t d, int32_t c, typename lane, int32_t l>
std::string sha3(const std::string& str)
{
    const char* cstr = str.c_str();
    uint32_t cstr_len = str.size();

    assert((1<<l) == sizeof(lane)*8);

    uint32_t w = (1<<l);

    uint32_t b = 5*5*w;                       // state width (bits)
    uint32_t r = b - c;                       // rate (int mult of 8) (bits)
    uint32_t num_rnds = 12 + 2*l;             // number of rounds

    uint32_t msg_len = cstr_len;              // number of chars in message (bytes)
    uint32_t digest_len = d / 8;              // number of chars in digest (bytes)
    uint32_t rate_len = r / 8;                // number of chars in rate (bytes)

    // padding
    uint32_t num_parts = 1 + (((msg_len*8) + 4) / r);     // number of partitions of padded message
    uint32_t pmsg_len = num_parts * rate_len;             // number of chars in padded message (bytes)

    // initialise padded msg as array of 8-bit ints, length of padded message, all set to zero
    // to be indexed 5*y + x for lane @ (x,y)
    uint8_t* pmsg = new uint8_t[pmsg_len];
    
    for (int i = 0; i < pmsg_len; ++i)
        pmsg[i] = 0;

    // fill first part of padded message with original message
    std::memcpy(pmsg, cstr, msg_len);

    // append 01 to message and apply padding rule
    set_bit<uint8_t, true>(pmsg[msg_len],       1, 1);
    set_bit<uint8_t, true>(pmsg[msg_len],       2, 1);
    set_bit<uint8_t, true>(pmsg[pmsg_len - 1],  7, 1);

    // absorption

    // initialise state and buffer as arrays of 25 lanes, state contains all zeros
    lane* state = new lane[25];
    lane* buffer = new lane[25];

    for(int i = 0; i < 25; ++i)
        state[i] = 0;

    // iterate through partitions of padded message
    for (int i = 0; i < num_parts; ++i)
    {
        // set buffer to be P_i || 0^c;
        for (int j = 0; j < 25; ++j)
            buffer[j] = 0;
        std::memcpy(buffer, pmsg + i, rate_len);

        // get state to be state XOR P_i || 0^c; this is the input for the sponge function
        for (int j = 0; j < 25; ++j)
            state[j] = state[j] ^ buffer[j];

        // sponge function (input = state, output = state)
        sha3_keccakp<lane>(l, num_rnds, state, buffer);
    }

    // squeezing 
    
    // initialise digest array of length r/8
    uint8_t* digest = new uint8_t[digest_len];

    for (int i = 0; i < digest_len; ++i)
        digest[i] = 0;

    // compute number of iterations of squeezing required to get digest by extracting r bits from state each round
    uint32_t num_sqz = d / r;
    if (d % r != 0)
        num_sqz = 1 + (d / r);
    
    uint32_t pos = 0;

    for (int i = 0; i < num_sqz; ++i)
    {
        // compute number of bytes to be extracted == min(rate_len, digest_len - pos)
        if (pos + rate_len > digest_len)
        {
            std::memcpy(digest + pos, state, digest_len - pos);
        }
        else
        {
            std::memcpy(digest + pos, state, rate_len);
            pos += rate_len;

            // sponge function (input = state, output = state)
            sha3_keccakp<lane>(l, num_rnds, state, buffer);
        }
    }

    std::string digest_str = "";

    for (int i = 0; i < digest_len; ++i)
    {
        digest_str += gv::to_hexcode<uint8_t>(digest[i]);
    }

    return digest_str;
}

} // namespace sha3

} // namespace gv