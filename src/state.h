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

#ifndef __state_h
#define __state_h

#include <config.h>

#include "ndebug.h"

extern pthread_t save_state_thread;

void save_state(const char *state_file_name, bool verbose);

bool restore_state(const char *state_file_name, const bool create_backup_file);

void start_save_state_thread(const char *state_file_name);

void save_queue_state(const char *state_file_name);

#endif /* __state_h */

/* vim: set autowrite expandtab: */
