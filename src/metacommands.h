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

#ifndef __metacommands_h
#define __metacommands_h

#include "ndebug.h"
#include "commands.h"
#include "nodelist.h"
#include "rules.h"
#include "addresses.h"

#define ITERATE_META_COMMANDS(COMMANDS) (meta_command_t *) &(COMMANDS)->head
#define NEXT_META_COMMAND(COMMAND) (meta_command_t *) (COMMAND->node.succ->succ ? COMMAND->node.succ : NULL)
#define HAS_NEXT_META_COMMAND(COMMAND) COMMAND->node.succ
#define REM_META_COMMANDS_HEAD(COMMANDS) (meta_command_t *) rem_head(COMMANDS)

/* assertions */

#ifdef NDEBUG
#define assert_meta_command(COMMAND) (void)(0)
#else /* NDEBUG */
#define assert_meta_command(COMMAND) assert_meta_command_ffl(COMMAND, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

/* metacommands.c */

typedef struct la_meta_command_s
{
        kw_node_t node;
        la_rule_t *rule;
        la_address_t *address;
        time_t meta_start_time;
        int factor;
} meta_command_t;

int meta_list_length(void);

void free_meta_list(void);

int check_meta_list(const la_command_t *const command, const int set_factor);

#endif /* __metacommands_h */

/* vim: set autowrite expandtab: */
