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

#ifndef __endqueue_h
#define __endqueue_h

#include <pthread.h>
#include <time.h>

#include <config.h>

#include "ndebug.h"
#include "nodelist.h"
#include "addresses.h"
#include "commands.h"
#include "binarytree.h"


extern pthread_t end_queue_thread;

extern pthread_mutex_t end_queue_mutex;


extern kw_list_t *queue_pointers;

typedef struct la_queue_pointer_s
{
        struct kw_node_s node;
        int duration;
        la_command_t *command;
} la_queue_pointer_t;

#ifndef CLIENTONLY
void update_queue_count_numbers(void);
#endif /* CLIENTONLY */

la_command_t *find_end_command(const la_address_t *address);

int remove_and_trigger(la_address_t *address);

void empty_end_queue(void);

void enqueue_end_command(la_command_t *end_command, time_t manual_end_time);

void init_end_queue(void);

void start_end_queue_thread(void);

la_command_t *first_command_in_queue(void);

la_command_t *next_command_in_queue(la_command_t *const command);

#ifndef CLIENTONLY
void empty_queue_pointers(void);
#endif /* CLIENTONLY */

kw_tree_node_t *get_root_of_queue(void);

int get_queue_length(void);

#endif /* __endqueue_h */

/* vim: set autowrite expandtab: */
