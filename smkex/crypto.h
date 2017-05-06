
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>

#define SESSION_KEY_LENGTH 32
#define SESSION_IV_LENGTH 12
#define SESSION_TAG_LENGTH 16
#define SESSION_NONCE_LENGTH 8

void hexdump(unsigned char * string, int length);
void sha1dump(unsigned char * string, int length);

int mp_aesgcm_encrypt(const unsigned char * ptext,
        size_t plen,
        const unsigned char * key,
        const unsigned char * iv,
        unsigned char * ctext,
        size_t * clen);

int mp_aesgcm_decrypt(const unsigned char * ctext,
        size_t clen,
        const unsigned char * key,
        const unsigned char * iv,
        unsigned char * ptext,
        size_t * plen);

/* KDF based of NIST SP 800-108 (HMAC + Counter)
 * Generates 64 pseudorandom bytes using HMAC-SHA-256
 */
void * nist_800_kdf(const void * in, size_t in_length, void * out, size_t * outlength);

#endif
