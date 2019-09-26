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
#include <stdbool.h>
#include <sodium.h>

#include "logactiond.h"

static unsigned char decrypted_message[MSG_LEN];


static bool
generate_key(unsigned char *key, unsigned int key_len)
{
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof salt);

        if (crypto_pwhash(key, key_len, "abcde", strlen("abcde"), salt,
                                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                crypto_pwhash_ALG_DEFAULT) == -1)
        {
                //la_debug("Unable to generate key");
                return false;
        }

        return true;
}


static bool
encrypt_message(unsigned char *buffer)
{
        if (sodium_init() < 0)
        {
                //la_debug("Unable to initialize libsodium");
                return false;
        }

        unsigned char key[crypto_secretbox_KEYBYTES];
        if (!generate_key(key, crypto_secretbox_KEYBYTES))
                return false;

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(&buffer[NONCE_IDX], sizeof nonce);

        printf("Before: %s\n", &buffer[MSG_IDX]);

        if (crypto_secretbox_easy(&buffer[MSG_IDX], &buffer[MSG_IDX], MSG_LEN,
                                &buffer[NONCE_IDX], key) == -1)
        {
                //la_debug("Encryption failed");
                return false;
        }

        printf("Between: %s\n", &buffer[MSG_IDX]);

        if (crypto_secretbox_open_easy(decrypted_message, &buffer[MSG_IDX], ENC_MSG_LEN,
                                &buffer[NONCE_IDX], key) == -1)
        {
                //la_debug("Decryption failed");
                return false;
        }

        printf("After: %s\n", decrypted_message);

        return true;
}

static void
pad(unsigned char * buffer, size_t msg_len)
{
        assert(msg_len <= MSG_LEN);
        assert(MSG_LEN - msg_len < 256);

        unsigned char pad = MSG_LEN - msg_len;
        for (int i=msg_len; i<MSG_LEN; i++)
                buffer[MSG_IDX+i] = pad;
}

char *
create_add_message(char *ip, char *rule, char *duration)
{
        /* TODO: error handling) */
        unsigned char *buffer = malloc(TOTAL_MSG_LEN);

        int msg_len = snprintf((char *) &buffer[MSG_IDX], MSG_LEN, "%c+%s,%s%s%s",
                        PROTOCOL_VERSION, ip, rule,
                        duration ? "," : "",
                        duration ? duration : "");
        if (msg_len > MSG_LEN-1)
        {
                //la_debug("String overflow!");
                return NULL;
        }

        pad(buffer, msg_len+1);
        if (!encrypt_message(buffer))
                return NULL;

        return (char *) buffer;
}

char *
create_remove_message(char *ip)
{
        /* TODO: error handling) */
        unsigned char *buffer = malloc(TOTAL_MSG_LEN);

        int msg_len = snprintf((char *) &buffer[MSG_IDX], MSG_LEN, "%c-%s",
                        PROTOCOL_VERSION, ip);
        if (msg_len > MSG_LEN-1)
        {
                //la_debug("String overflow!");
                return NULL;
        }

        pad(buffer, msg_len+1);
        if (!encrypt_message(buffer))
                return NULL;

        return (char *) buffer;
}

/*
 * Construct an a message. Buffer must be supplied, will not be allocated.
 *
 * Message format is
 *
 *      "+<ip-address>,<rule-name>,<duation-in-seconds>"
 *
 * or
 *
 *      "+<ip-address>,<rule-name>"
 *
 * if send_duration is false.
 */

/*bool
create_add_entry_message(char *buffer, size_t buf_len, la_command_t *command,
                bool send_duration)
{
        int message_len;
        if (send_duration)
                message_len = snprintf(buffer, buf_len-1, "+%s,%s,%u",
                                command->address->text, command->rule_name,
                                command->duration);
        else
                message_len = snprintf(buffer, buf_len-1, "+%s,%s",
                                command->address->text, command->rule_name);

        return (message_len <= buf_len-1);
}*/


/* vim: set autowrite expandtab: */
