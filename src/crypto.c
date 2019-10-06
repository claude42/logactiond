/*
 *  logactiond - trigger actions based on logfile contents
 *  Copyright (C) 2019  Klaus Wissmann

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

#include <assert.h>
#include <string.h>
#include <syslog.h>
#include <sodium.h>
#include <stdlib.h>

#include "logactiond.h"

static char *send_key_password;
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
generate_key(unsigned char *key, unsigned int key_len, char *password,
                unsigned char *salt)
{
	assert(key); assert(key_len > 0); assert(password); assert(salt);
        if (crypto_pwhash(key, key_len, password, strlen(password), salt,
                                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                crypto_pwhash_ALG_DEFAULT) == -1)
        {
                la_log_errno(LOG_ERR, "Unable to encryption generate key");
                return false;
        }

        return true;
}


bool
generate_send_key_and_salt(unsigned char *key, char *password,
                unsigned char *salt)
{
	/* First initialize salt with randomness */
        randombytes_buf(salt, crypto_pwhash_SALTBYTES);

	/* Then generate secret key from password and salt */
        return generate_key(key, crypto_secretbox_KEYBYTES, password, salt);
}

bool
decrypt_message(char *buffer, char *password, la_address_t *from_addr)
{
	assert(buffer); assert(password);
        unsigned char *ubuffer = (unsigned char *) buffer;

        if (sodium_init() < 0)
        {
                la_log_errno(LOG_ERR, "Unable to  initialize libsodium");
                return false;
        }

        /* check wether salt is the same as last time for host. If not,
         * regenerate key */
        if (sodium_memcmp(&(from_addr->salt), &ubuffer[SALT_IDX],
                                crypto_pwhash_SALTBYTES))
        {
                memcpy(&(from_addr->salt), &ubuffer[SALT_IDX], crypto_pwhash_SALTBYTES);
                if (!generate_key(from_addr->key, crypto_secretbox_KEYBYTES,
                                        password, &ubuffer[SALT_IDX]))
                {
                        la_log_errno(LOG_ERR, "Unable to generate receive key for "
                                        "host %s", from_addr->text);
                        return false;
                }
        }

	/* Decrypt encrypted message with key and nonce */
        if (crypto_secretbox_open_easy(&ubuffer[MSG_IDX], &ubuffer[MSG_IDX],
                                ENC_MSG_LEN, &ubuffer[NONCE_IDX],
                                from_addr->key) == -1)
        {
                la_log_errno(LOG_ERR, "Unable to decrypt message from host %s",
                                from_addr->text);
                return false;
        }
        return true;
}

bool
encrypt_message(char *buffer, char *password)
{
	assert(buffer); assert(password);
        unsigned char *ubuffer = (unsigned char *) buffer;

        if (sodium_init() < 0)
        {
                la_log_errno(LOG_ERR, "Unable to  initialize libsodium");
                return false;
        }

        if (!send_key_password || strcmp(send_key_password, password))
        {
                free(send_key_password);
                send_key_password = xstrdup(password);
                generate_send_key_and_salt(send_key, password, send_salt);
        }

        memcpy(&ubuffer[SALT_IDX], send_salt, crypto_pwhash_SALTBYTES);

	/* Initialize nonce with random data */
        randombytes_buf(&ubuffer[NONCE_IDX], crypto_secretbox_NONCEBYTES);

	/* And then encrypt the the message with key and nonce */
        if (crypto_secretbox_easy(&ubuffer[MSG_IDX], &ubuffer[MSG_IDX], MSG_LEN,
                                &ubuffer[NONCE_IDX], send_key) == -1)
        {
                la_log_errno(LOG_ERR, "Unable to encrypt message");
                return false;
        }

        return true;
}

/* 
 * Apply PKCS#7 padding to buffer.
 */

void
pad(char *buffer, size_t msg_len)
{
	assert(buffer);
        assert(msg_len > 0); assert(msg_len <= MSG_LEN);
        assert(MSG_LEN - msg_len < 256);

        unsigned char pad = MSG_LEN - msg_len;
        for (int i=msg_len; i<MSG_LEN; i++)
                buffer[MSG_IDX+i] = pad;
}

#endif /* NOCRYPTO */

/* vim: set autowrite expandtab: */
