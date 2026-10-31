/* Source: cairn-lang 6748510 src/sha256.h (sha256_words and the
   front/u256.h include cut). */
/* SHA-256 (FIPS 180-4), one-shot: the FROST(secp256k1, SHA-256) hashes
   and expand_message_xmd (S7, O90, O91). The round constants, the
   initial hash and the compression are exported for the gadget
   (sha256gadget.h, quorum-lang S11 H3a P3). */
#ifndef LANG_CRYPTO_SHA256_H
#define LANG_CRYPTO_SHA256_H
#include <stddef.h>
#include <stdint.h>

void sha256(const unsigned char *data, size_t size, unsigned char digest[32]);
/* Section 4.2.2: the 64 round constants K. */
extern const uint32_t sha256_round_constant[64];
/* Section 5.3.3: STATE = the initial hash value H(0). */
void sha256_initial(uint32_t state[8]);
/* Section 6.2.2: one 64-byte BLOCK into STATE. */
void sha256_compress(uint32_t state[8], const unsigned char block[64]);
#endif
