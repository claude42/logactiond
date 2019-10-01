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


#include <config.h>

#include <assert.h>
#include <string.h>
#include <syslog.h>
#include <sodium.h>
#include <stdlib.h>
#include <stdio.h>

#include "logactiond.h"

static unsigned char decrypted_message[MSG_LEN];

/*
 * Message format:
 *  - First char is always the protocol version encoded as a single ASCII character
 *  - Second char is the command - encoded as a single ASCII character
 *  - Rest is command specific
 *  - Maximum message size is 175 (protocol version '0') determined by the '+'
 *    command.
 *
 * Accepted commands:
 *
 *      "0+<ip-address>,<rule-name>,<duation-in-seconds>"
 *      "0-<ip-address>
 *
 * Example structure:
 *      "0+<ip-address>/<prefix>,<rule-name>,<duration-in-seconds>0"
 *       || |          | |      | |         | |                   |
 *       || |          | |      | |         | |                   +-   1 byte
 *       || |          | |      | |         | +---------------------  20 bytes
 *       || |          | |      | |         +-----------------------   1 byte
 *       || |          | |      | +--------------------------------- 100 bytes
 *       || |          | |      +-----------------------------------   1 byte
 *       || |          | +------------------------------------------   3 bytes
 *       || |          +--------------------------------------------   1 byte
 *       || +-------------------------------------------------------  46 bytes
 *       |+---------------------------------------------------------   1 byte
 *       +----------------------------------------------------------   1 byte
 *                                                                  ==========
 *                                                                   175 bytes
 */

/*
 * Parses message and will populate address, rule and duration. If one of
 * parameters address, rule, duration is NULL, it will be skipped.
 *
 *
 * Please note: this function will modify the message buffer!
 */

#ifndef CLIENTONLY

bool
parse_add_entry_message(char *message, la_address_t **address, la_rule_t **rule,
                int *duration)
{
        assert(message);
        la_debug("parse_add_entry_message(%s)", message);

        if (*message != PROTOCOL_VERSION)
        {
                la_log(LOG_ERR, "Wrong protocol version '%c'!", *message);
                return false;
        }

        if (*(message+1) != '+')
        {
                la_log(LOG_ERR, "Unexpected message command '%c'!", *(message+1));
                return false;
        }

        char *comma = strchr(message, ',');
        if (!comma)
        {
                la_log(LOG_ERR, "Illegal command %s!", message);
                return false;
        }
        *comma = '\0';
        
        char *comma2 = strchr(comma+sizeof(char), ',');
        if (comma2)
                *comma2 = '\0';


        if (address)
        {
                *address = create_address(message+2*sizeof(char));
                if (!*address)
                {
                        la_log(LOG_ERR, "Cannot convert address in command %s!", message);
                        return false;
                }
                la_debug("Found address %s", (*address)->text);
        }

        if (rule)
        {
                *rule = find_rule(comma+sizeof(char));
                if (!*rule)
                {
                        *comma = ',';
                        if (comma2)
                                *comma2 = ',';
                        la_log_verbose(LOG_ERR, "Ignoring remote message \'%s\' "
                                        "- rule not active on local system", message);
                        free_address(*address);
                        return false;
                }
                la_debug("Found rule %s.", (*rule)->name);
        }

        if (duration)
        {
                *duration = 0;
                if (comma2)
                {
                        char *endptr;
                        *duration = strtol(comma2+sizeof(char), &endptr, 10);
                        if (*endptr != '\0')
                        {
                                la_log(LOG_ERR, "Spurious characters in command %s!", message);
                                free_address(*address);
                                return false;
                        }
                }
        }

        return true;
}

#endif /* CLIENTONLY */

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
decrypt_message(char *buffer, char *password)
{
	assert(buffer); assert(password);
        unsigned char *ubuffer = (unsigned char *) buffer;

        if (sodium_init() < 0)
        {
                la_log_errno(LOG_ERR, "Unable to  initialize libsodium");
                return false;
        }

	/* Generate secret key based on password and transmitted salt */
        unsigned char key[crypto_secretbox_KEYBYTES];
        if (!generate_key(key, crypto_secretbox_KEYBYTES, password,
                                &ubuffer[SALT_IDX]))
                return false;

	/* Decrypt encrypted message with key and nonce */
        if (crypto_secretbox_open_easy(&ubuffer[MSG_IDX], &ubuffer[MSG_IDX],
                                ENC_MSG_LEN, &ubuffer[NONCE_IDX], key) == -1)
        {
                la_log_errno(LOG_ERR, "Unable to decrypt message");
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

	/* First initialize salt with randomness */
        randombytes_buf(&ubuffer[SALT_IDX], crypto_pwhash_SALTBYTES);

	/* Then generate secret key from password and salt */
        unsigned char key[crypto_secretbox_KEYBYTES];
        if (!generate_key(key, crypto_secretbox_KEYBYTES, password,
                                &ubuffer[SALT_IDX]))
                return false;

	/* Initialize nonce with random data */
        randombytes_buf(&ubuffer[NONCE_IDX], crypto_secretbox_NONCEBYTES);

	/* And then encrypt the the message with key and nonce */
        if (crypto_secretbox_easy(&ubuffer[MSG_IDX], &ubuffer[MSG_IDX], MSG_LEN,
                                &ubuffer[NONCE_IDX], key) == -1)
        {
                la_log_errno(LOG_ERR, "Unable to encrypt message");
                return false;
        }

        return true;
}

/* 
 * Apply PKCS#7 padding to buffer.
 */

static void
pad(char *buffer, size_t msg_len)
{
	assert(buffer);
        assert(msg_len > 0); assert(msg_len <= MSG_LEN);
        assert(MSG_LEN - msg_len < 256);

        unsigned char pad = MSG_LEN - msg_len;
        for (int i=msg_len; i<MSG_LEN; i++)
                buffer[MSG_IDX+i] = pad;
}

char *
create_add_message(char *ip, char *rule, char *duration)
{
	assert(ip); assert(rule);

        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%c+%s,%s%s%s",
                        PROTOCOL_VERSION, ip, rule,
                        duration ? "," : "",
                        duration ? duration : "");
        if (msg_len > MSG_LEN-1)
                return NULL;

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}

char *
create_remove_message(char *ip)
{
	assert(ip);
        char *buffer = xmalloc(TOTAL_MSG_LEN);

        int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, "%c-%s",
                        PROTOCOL_VERSION, ip);
        if (msg_len > MSG_LEN-1)
                return NULL;

        /* pad right here, cannot hurt even if we don't encrypt... */
        pad(buffer, msg_len+1);

        return buffer;
}


/* vim: set autowrite expandtab: */
