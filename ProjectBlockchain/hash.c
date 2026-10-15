#include "hash.h"

/*
unsigned char* SSHA(const unsigned char* msg, size_t length) {
    unsigned char A, B, C, D, E; //Initial Seed Value
    A = 56;
    B = 99;
    C = 102;
    D = 67;
    E = 76;

    for (int i = 0; i < length; i++) {
        for (int round = 0; round < 8; round++) {
            unsigned char g = (B & C) | (C & D);
            unsigned char old_A = A;
            A = ~A & 0xFF;
            B = ~(B << 1) & 0xFF;
            E = (g + msg[i] + B);
            D = A ^ B;
            C = (A + E);
            A = E;
            B = old_A;
        }
      
    }
    unsigned char* digest = (unsigned char*)malloc(DIGEST_SIZE * sizeof(unsigned char));
    digest[0] = A;
    digest[1] = B;
    digest[2] = C;
    digest[3] = D;
	digest[4] = E; // Logical error: the digest should be 5 bytes, but the loop only computes 4 bytes
    return digest;
}
*/


/*
 * SSHA2: Custom Scrambled Hash Algorithm 2
 *
 * Output: 32-byte digest.
 *
 * IMPORTANT:
 * This is a custom, non-standard hash construction.
 * Do not use it for security-sensitive applications.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define SSHA2_DIGEST_SIZE 32

static uint32_t rotl32(uint32_t x, unsigned int n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t scramble(uint32_t x)
{
    x ^= x >> 16;
    x *= UINT32_C(0x7FEB352D);
    x ^= x >> 15;
    x *= UINT32_C(0x846CA68B);
    x ^= x >> 16;
    return x;
}

unsigned char* SSHA(const unsigned char* msg, size_t length)
{
    if (msg == NULL && length != 0)
        return NULL;

    unsigned char* digest =
        (unsigned char*)malloc(SSHA2_DIGEST_SIZE);

    if (digest == NULL)
        return NULL;

    /* Fixed initial seed values */
    uint32_t state[8] = {
        UINT32_C(0x243F6A88),
        UINT32_C(0x85A308D3),
        UINT32_C(0x13198A2E),
        UINT32_C(0x03707344),
        UINT32_C(0xA4093822),
        UINT32_C(0x299F31D0),
        UINT32_C(0x082EFA98),
        UINT32_C(0xEC4E6C89)
    };

    const uint32_t constants[8] = {
        UINT32_C(0x9E3779B9),
        UINT32_C(0x7F4A7C15),
        UINT32_C(0xF39CC060),
        UINT32_C(0x106AA070),
        UINT32_C(0xC2B2AE35),
        UINT32_C(0x27D4EB2F),
        UINT32_C(0x165667B1),
        UINT32_C(0x85EBCA77)
    };

    /*
     * Absorb every input byte.
     * The byte position and input length affect the mixing.
     */
    for (size_t i = 0; i < length; ++i) {
        uint32_t b = (uint32_t)msg[i];
        unsigned int a = (unsigned int)(i & 7U);
        unsigned int c = (a + 3U) & 7U;
        unsigned int d = (a + 5U) & 7U;

        state[a] ^= b + constants[a]
            + (uint32_t)i;

        state[a] = rotl32(
            state[a],
            (unsigned int)((i % 23U) + 5U)
        );

        state[c] += state[a] ^ constants[d];
        state[c] = rotl32(state[c], 13U);

        state[d] ^= scramble(state[c] + b);
        state[d] += rotl32(state[a], 7U);

        /* Cross-state diffusion */
        for (unsigned int r = 0; r < 4; ++r) {
            unsigned int x = (a + r + 1U) & 7U;
            unsigned int y = (a + r + 4U) & 7U;

            state[x] +=
                rotl32(state[y] ^ state[a],
                    (r * 5U) + 3U);

            state[x] ^= scramble(
                state[y] + constants[(x + r) & 7U]
            );
        }
    }

    /*
     * Finalization: incorporate the input length,
     * then diffuse the state through additional rounds.
     */
    uint32_t lo = (uint32_t)length;
    uint32_t hi = (uint32_t)(
        (uint64_t)length >> 32
        );

    state[0] ^= lo;
    state[1] ^= hi;
    state[2] ^= rotl32(lo, 11U);
    state[3] ^= rotl32(hi, 17U);

    for (unsigned int round = 0; round < 16; ++round) {
        for (unsigned int i = 0; i < 8; ++i) {
            unsigned int j = (i + 1U) & 7U;
            unsigned int k = (i + 5U) & 7U;

            uint32_t v = state[i] + constants[
                (i + round) & 7U
            ];

            v ^= rotl32(
                state[j],
                ((i + round) % 29U) + 1U
            );

            v += scramble(
                state[k] ^ (uint32_t)round
            );

            state[i] = rotl32(
                v,
                ((i * 3U + round) % 31U) + 1U
            );
        }
    }

    /* Serialize eight 32-bit words into 32 digest bytes. */
    for (unsigned int i = 0; i < 8; ++i) {
        digest[i * 4U + 0U] =
            (unsigned char)(state[i] >> 24);
        digest[i * 4U + 1U] =
            (unsigned char)(state[i] >> 16);
        digest[i * 4U + 2U] =
            (unsigned char)(state[i] >> 8);
        digest[i * 4U + 3U] =
            (unsigned char)state[i];
    }

    return digest;
}





int digest_equal(struct Digest digest1, struct Digest digest2) {
    return ((digest1.hash0 == digest2.hash0) &&
        (digest1.hash1 == digest2.hash1) &&
        (digest1.hash2 == digest2.hash2) &&
        (digest1.hash3 == digest2.hash3) &&
        (digest1.hash4 == digest2.hash4));
    
}

void printDigest(struct Digest digest) {
    printf("%d %d %d %d %d\n", digest.hash0, digest.hash1, digest.hash2, digest.hash3, digest.hash4);
}