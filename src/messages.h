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
#define CMD_ADD '+'
#define CMD_ADD_STR "+"
#define CMD_DEL '-'
#define CMD_FLUSH 'F'
#define CMD_RELOAD 'R'
#define CMD_SHUTDOWN 'S'
#define CMD_SAVE_STATE '>'
#define CMD_CHANGE_LOG_LEVEL 'L'
#define CMD_RESET_COUNTS '0'
#define CMD_SYNC 'X'
#define CMD_STOPSYNC 'x'
#define CMD_DUMP_STATUS 'D'
#define CMD_ENABLE_RULE 'Y'
#define CMD_DISABLE_RULE 'N'
#define CMD_UPDATE_STATUS_MONITORING 'M'
#define CMD_UPDATE_WATCHING 'W'


/* Length of unencrypted message*/
#define MSG_LEN 180

/* Some message parts */
#define MSG_ADDRESS_LENGTH 50
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
#define TOTAL_MSG_LEN (ENC_MSG_LEN + crypto_secretbox_NONCEBYTES + crypto_pwhash_SALTBYTES)
#else
#define TOTAL_MSG_LEN MSG_LEN
#endif

#define MSG_IDX 0
#define SALT_IDX ENC_MSG_LEN
#define NONCE_IDX (ENC_MSG_LEN+crypto_pwhash_SALTBYTES)

#ifndef CLIENTONLY
int parse_add_entry_message(const char *message, la_address_t *address,
                la_rule_t **rule, time_t *end_time, int *factor);

void parse_message_trigger_command(const char *buf, la_address_t *from_addr);
#endif /* CLIENTONLY */

bool init_add_message(char *buffer, const char *ip, const char *rule, const char *end_time, const char *factor);

int print_add_message(FILE *stream, const la_command_t *command);

bool init_del_message(char *buffer, const char *ip);

bool init_empty_queue_message(char *buffer);

bool init_simple_message(char *buffer, char message_command, const char *message_payload);

bool init_flush_message(char *buffer);

bool init_reload_message(char *buffer);

bool init_shutdown_message(char *buffer);

bool init_save_message(char *buffer);

bool init_restore_message(char *buffer);

bool init_log_level_message(char *buffer, int new_log_level);

bool init_status_monitoring_message(char *buffer, int new_status);

bool init_watching_message(char *buffer, int new_status);

bool init_reset_counts_message(char *buffer);

bool init_sync_message(char *buffer, const char *host);

bool init_stopsync_message(char *buffer);

bool init_dump_message(char *buffer);

bool init_enable_message(char *buffer, const char *rule);

bool init_disable_message(char *buffer, const char *rule);

#endif /* __messages_h */

/* vim: set autowrite expandtab: */
