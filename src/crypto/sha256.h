/* Source: cairn-lang 6748510 src/sha256.h (sha256_words and the
   front/u256.h include cut). */
/* SHA-256 (FIPS 180-4), one-shot: the FROST(secp256k1, SHA-256) hashes
   and expand_message_xmd (S7, O90, O91). */
#ifndef LANG_CRYPTO_SHA256_H
#define LANG_CRYPTO_SHA256_H
#include <stddef.h>

void sha256(const unsigned char *data, size_t size, unsigned char digest[32]);
#endif
