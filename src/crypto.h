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

#ifndef __crypto_h
#define __crypto_h

#include <stdbool.h>

#include "ndebug.h"
#include "addresses.h"

bool generate_send_key_and_salt(const char *password);

bool decrypt_message(char *buffer, const char *password, la_address_t *from_addr);

bool encrypt_message(char *buffer);

void pad(char *buffer, size_t msg_len);

#endif /* __crypto_h */

/* vim: set autowrite expandtab: */
