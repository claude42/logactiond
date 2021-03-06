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

#ifndef __remote_h
#define __remote_h

#include "ndebug.h"

void send_message_to_all_remote_hosts(const char *message);

void send_add_entry_message(const la_command_t *command, const la_address_t *address);

void start_all_remote_threads(void);

void send_message_to_single_address(const char *message,
                const la_address_t *remote_address);

void sync_entries(const char *buffer, la_address_t *from_addr);

void stop_syncing(void);

#endif /* __remote_h */

/* vim: set autowrite expandtab: */
