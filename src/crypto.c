/*
 *  logactiond - trigger actions based on logfile contents
 *  Copyright (C) 2019-2021 Klaus Wissmann

 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef NOCRYPTO
#include <config.h>

#include <string.h>
#include <stdbool.h>
#include <stddef.h>

#include "ndebug.h"
#include "crypto.h"
#include "logging.h"
#include "messages.h"
#include "addresses.h"
#include "misc.h"

#ifdef WITH_LIBSODIUM
#include <sodium.h>

static unsigned char send_key[crypto_secretbox_KEYBYTES];
static unsigned char send_salt[crypto_pwhash_SALTBYTES];

/*
 * Encrypted message format:
 *      <Encrypted message><salt><nonce>
 *       |                  |     |
 *       |                  |     +- crypto_pwhash_NONCEBYTES
 *       |                  +------- crypto_pwhash_SALTBYTES
 *       +-------------------------- 180 bytes payload
 */

static bool
generate_key(unsigned char *const key, const size_t key_len,
                const char *const password, const unsigned char *const salt)
{
	assert(key); assert(key_len > 0); assert(password); assert(salt);
        return (crypto_pwhash(key, key_len, password, strlen(password), salt,
                                crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,
                                crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE,
                                crypto_pwhash_ALG_ARGON2I13) == 0);
}


bool
generate_send_key_and_salt(const char *const password)
{
	/* First initialize salt with randomness */
        randombytes_buf(send_salt, crypto_pwhash_SALTBYTES);

	/* Then generate secret key from password and salt */
        if (!generate_key(send_key, crypto_secretbox_KEYBYTES, password, send_salt))
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to generate encryption key!");

        return true;
}

/*
 * Returns true if salt has not changed.
 */

static bool
same_salt_as_before(const unsigned char *const buffer, la_address_t *const from_addr)
{
        assert(buffer); assert_address(from_addr);
        if (!from_addr->salt)
                return NULL;

        return !sodium_memcmp(from_addr->salt, &buffer[SALT_IDX],
                        crypto_pwhash_SALTBYTES);
}

static bool
copy_salt_and_generate_key_for_address(const unsigned char *const ubuffer,
                const char *const password, la_address_t *const from_addr)
{
        if (!from_addr->salt)
                from_addr->salt = xmalloc(crypto_pwhash_SALTBYTES);
        memcpy(from_addr->salt, &ubuffer[SALT_IDX], crypto_pwhash_SALTBYTES);

        if (!from_addr->key)
                from_addr->key = xmalloc(crypto_secretbox_KEYBYTES);
        return generate_key(from_addr->key, crypto_secretbox_KEYBYTES,
                                password, &ubuffer[SALT_IDX]);
}

/*
 * Will update from_addr->salt, from_addr->key if necessary.
 */
bool
decrypt_message(char *const buffer, const char *const password,
                la_address_t *const from_addr)
{
	assert(buffer); assert(password); assert_address(from_addr);
        unsigned char *const ubuffer = (unsigned char *const) buffer;

        if (sodium_init() < 0)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to  initialize libsodium!");

        /* check wether salt is the same as last time for host. If not,
         * copy new salt and regenerate key */
        if (!same_salt_as_before(ubuffer, from_addr))
        {
                if (!copy_salt_and_generate_key_for_address(ubuffer, password,
                                from_addr))
                        LOG_RETURN_ERRNO(false, LOG_ERR,
                                        "Unable to generate receive key for "
                                        "host %s!", from_addr->text);
        }

	/* Decrypt encrypted message with key and nonce */
        if (crypto_secretbox_open_easy(&ubuffer[MSG_IDX], &ubuffer[MSG_IDX],
                                ENC_MSG_LEN, &ubuffer[NONCE_IDX],
                                from_addr->key) == -1)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to decrypt message from host %s",
                                from_addr->text);
        return true;
}

bool
encrypt_message(char *buffer)
{
	assert(buffer);
        unsigned char *ubuffer = (unsigned char *) buffer;

        if (sodium_init() < 0)
                LOG_RETURN(false, LOG_ERR, "Unable to  initialize libsodium!");

        memcpy(&ubuffer[SALT_IDX], send_salt, crypto_pwhash_SALTBYTES);

	/* Initialize nonce with random data */
        randombytes_buf(&ubuffer[NONCE_IDX], crypto_secretbox_NONCEBYTES);

	/* And then encrypt the the message with key and nonce */
        if (crypto_secretbox_easy(&ubuffer[MSG_IDX], &ubuffer[MSG_IDX], MSG_LEN,
                                &ubuffer[NONCE_IDX], send_key) == -1)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to encrypt message!");

        return true;
}
#endif /* WITH_LIBSODIUM */

/* 
 * Apply PKCS#7 padding to buffer.
 */

void
pad(char *buffer, const size_t msg_len)
{
	assert(buffer);
        assert(msg_len > 0); assert(msg_len <= MSG_LEN);
        assert(MSG_LEN - msg_len < 256);

        const unsigned char pad = MSG_LEN - msg_len;
        for (size_t i=msg_len; i<MSG_LEN; i++)
                buffer[MSG_IDX+i] = pad;
}

#endif /* NOCRYPTO */

/* vim: set autowrite expandtab: */
