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

#ifndef __messages_h
#define __messages_h

#include <config.h>

#include "ndebug.h"
#include "addresses.h"
#include "rules.h"
#include "commands.h"

/* Remote protocol */

#define PROTOCOL_VERSION '0'
#define PROTOCOL_VERSION_STR "0"

/* Length of unencrypted message*/
#define MSG_LEN 180

/* Some message parts */
#define MSG_ADDRESS_LENGTH 50
#define MSG_RULE_LENGTH 100
#define MSG_END_TIME_LENGTH 20
#define MSG_FACTOR_LENGTH 4

#ifdef WITH_LIBSODIUM
/* Length of encrypted message (i.e. incl. MAC */
#define ENC_MSG_LEN MSG_LEN + crypto_secretbox_MACBYTES
/* Length of whole message that will be send, i.e.
 * - nonce
 * - MAC
 * - the encrypted message
 */
#define TOTAL_MSG_LEN ENC_MSG_LEN + crypto_secretbox_NONCEBYTES + crypto_pwhash_SALTBYTES
#else
#define TOTAL_MSG_LEN MSG_LEN
#endif

#define MSG_IDX 0
#define SALT_IDX ENC_MSG_LEN
#define NONCE_IDX ENC_MSG_LEN+crypto_pwhash_SALTBYTES

#ifndef CLIENTONLY
int parse_add_entry_message(const char *message, la_address_t **address,
                la_rule_t **rule, time_t *end_time, int *factor);

void parse_message_trigger_command(const char *buf, const char *from);
#endif /* CLIENTONLY */

char *create_add_message(const char *ip, const char *rule, const char *end_time, const char *factor);

int print_add_message(FILE *stream, const la_command_t *command);

char *create_del_message(const char *ip);

char *create_empty_queue_message(void);

char *create_simple_message(char c);

char *create_flush_message(void);

char *create_reload_message(void);

char *create_shutdown_message(void);

char *create_save_message(void);

char *create_restore_message(void);

char *create_log_level_message(int new_log_level);

char *create_reset_counts_message(void);

char *create_sync_message(const char *host);

char *create_dump_message(void);

char *create_enable_message(const char *rule);

char *create_disable_message(const char *rule);

#endif /* __messages_h */

/* vim: set autowrite expandtab: */
