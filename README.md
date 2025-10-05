# Cryptography

This repository contains my implementations of cryptography-related algorithms and useful functions.

The hashing functions I've implemented are:
* ___SHA1___
* ___SHA3-256___

## Table of Contents
- [Requirements](#requirements)
- [Usage](#usage)
- [Hashing](#hashing)
<!--- [Encryption](#encryption)-->

## Usage

### SHA3-256 ###

A simple test file for SHA3-256 is included for the input `"hello"`. Simply build with
```
g++ sha3_256_test.cpp -o sha3_256
```
Then run with
```
./sha3_256 <your_input_here>
```

If using in a separate project, include the headers
```cpp
#include "sha3_256.hpp"
```
Using the `gv::sha3_256` namespace, call the `digest` function, passing in a `std::string` object, that ***must already exist***. For example,
```cpp
#include <iostream>
#include "sha3_256.hpp"

int main() {
    std::string input = "hello";
    std::string hash = gv::sha3_256::digest(input);

    std::cout << "Input: " << input << std::endl;
    std::cout << "SHA3-256 hash: " << hash << std::endl;
    std::cout << "Should be: 3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392" << std::endl;
}
```

### SHA1 ###

The same steps for SHA3-256 are applicable for SHA1. To test that the implementation is working, build the test file and run with an input of your choice.

```
g++ sha1_test.cpp -o sha1_test
```

```
./sha1_test hello
```

The output should be
```
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
```

## Hashing

Hashing functions are one-way encryption algorithms that process an arbitrary-length input to give a fixed-length "message digest". Hashing functions should exhibit certain properties:
* The probability that modifying the input will significantly change the output is very high
* Non-reversibility, i.e. there exists no function that reverses the hashing
* Uniformity, i.e. minimal collisions of hash mappings of distinct inputs


### SHA3-256

Here is some info about the SHA3-256 algorithm.

Secure Hash Algorithm-3 is based on the Keccak algorithm. This implementation follows the original paper available at https://doi.org/10.6028/NIST.FIPS.202. SHA3-256 is the variant that produces a 256-bit digest. The SHA3 algorithm uses a 'sponge' construction, where the input is 'absorbed' into the sponge and the output is 'squeezed' out. The algorithm uses an internal state array of length 1600 bits. The input determines how this array is permuted, i.e. the input becomes a permutation function. The output is then taken from this internal state array. The steps of the SHA3-256 algorithm are as follows:

#### Initialisation of internal state ####
The internal state array begins as 25 * 64-bit zero words, i.e. 1600 bits all set to zero. The input message is then padded to fit into 1088-bit blocks, i.e. has a length that is divisible by 1088. The padding rule is:
`<input>10...01`, i.e. if the input is `10110010`, then this would be modifed to be `101100101000...0001`, where the `...` would be 1072 zeros. 

#### Absorb phase ####

For each 1088-bit block in the input, you

1. XOR the first 1088 bits of the internal state array with this block

2. For 24 rounds perform 5 permutations ($\theta$, $\rho$, $\pi$, $\chi$, $\iota$) sequentially on the internal state array. This makes up the Keccak-f[1600] permutation. These permutations view the 1600 bits as a 3D array, in particular, a 5 * 5 grid of 64-bit 'lanes'. The role of each permutation is given by:

| Permutation | Description |
|------|--------|
| $\theta$ | Mixes bits across all columns for diffusion |
| $\rho$ | Rotates bits within each 64-bit lane |
| $\pi$ | Permutes the lane positions in the 5*5 grid |
| $\chi$ | Nonlinear mixing (bitwise AND, NOT, XOR)
| $\iota$ | Adds a round constant to break symmetry|

#### Squeeze phase ####

Simply take the first 256 bits of the internal state.

<!--## Encryption

Symmetric encryption functions take a message and private key as inputs to produce an encrypted message. The same private key is then used to decrypt the message.

The symmetric encryption functions implemented thus far are:
* ...
-->