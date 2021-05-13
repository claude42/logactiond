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

#include <time.h>

#include "ndebug.h"
#include "metacommands.h"
#include "commands.h"
#include "logging.h"
#include "misc.h"
#include "binarytree.h"

static kw_tree_t *meta_list;

int
meta_list_length(void)
{
        if (!meta_list)
                return 0;

        return meta_list->count;
}

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
static void
free_meta_command(la_meta_command_t *const meta_command)
{
        la_vdebug_func(NULL);
        assert(meta_command);

        free_address(meta_command->address);
        free(meta_command);
}

void
free_meta_list(void)
{
        la_vdebug_func(NULL);
        if (!meta_list)
                return;
        assert_tree(meta_list);

        free_tree(meta_list, (void (*)(const void *)) free_meta_command, false);
}

static la_meta_command_t *
create_meta_command(const la_command_t *const command)
{
        assert_command(command); assert_address(command->address);
        la_debug_func(command->address->text);

        la_meta_command_t *result = xmalloc(sizeof *result);
        result->adr_node.payload = result;

        result->rule = command->rule;
        result->address = dup_address(command->address);
        result->meta_start_time = xtime(NULL);
        result->factor = 1;

        return result;
}

/*
 * Returns a meta_command with the same IP address as the specified command -
 * if one is on the meta_list and has not expired yet. Returns NULL otherwise.
 *
 * While searching through meta_list, will remove (and free) all meta_commands
 * which have already expired.
 */

static la_meta_command_t *
find_on_meta_list(const la_command_t *const command)
{
        assert_command(command); assert_address(command->address);
        la_debug_func(command->address->text);

        const time_t now = xtime(NULL);

        assert_tree(meta_list);

        kw_tree_node_t *node = meta_list->root;
        for (;;)
        {
                if (!node)
                        return NULL;

                la_meta_command_t *mcmd = (la_meta_command_t *) node->payload;
                assert(mcmd);
                const int cmp = adrcmp(mcmd->address, command->address);

                if (now >= mcmd->meta_start_time + mcmd->rule->meta_period)
                {
                        /* Remove expired commands from meta list */
                        kw_tree_node_t *tmp = node;
                        node = remove_tree_node(meta_list, node);
                        free_meta_command((la_meta_command_t *) tmp->payload);
                }
                else if (cmp == 0)
                {
                        return mcmd;
                }
                else if (cmp < 0 && node->right)
                {
                        node = node->right;
                }
                else if (cmp > 0 && node->left)
                {
                        node = node->left;
                }
                else
                {
                        return NULL;
                }
        }

        /* control flow must not reach this point */
        assert(false);
        return NULL;
}

static int
cmp_meta_commands(const void *p1, const void *p2)
{
        return adrcmp(((la_meta_command_t *) p1)->address, ((la_meta_command_t *) p2)->address);
}

/*
 * Checks whether a coresponding command is already on the meta_list (see
 * find_on_meta_list(). If so, increases factor, resets meta_start_time and
 * returns the factor to the calling function.
 *
 * If nothings found on the list, create new meta_command with default factor.
 */

int
check_meta_list(const la_command_t *const command, const int set_factor)
{
        assert_command(command); assert(command->address);
        la_debug("check_meta_list(%s, %u)", command->address->text,
                        command->duration);

        if (!meta_list)
                meta_list = create_tree();

        const time_t now = xtime(NULL);

        la_meta_command_t *meta_command = find_on_meta_list(command);
        if (!meta_command)
        {
                meta_command = create_meta_command(command);
                assert(meta_command);
                if (set_factor)
                        meta_command->factor = set_factor;
                meta_command->meta_start_time = now +
                        (long) meta_command->factor * command->duration;
                add_to_tree(meta_list, &meta_command->adr_node, cmp_meta_commands);
        }
        else if (now > meta_command->meta_start_time)
        {
                if  (meta_command->factor == -1 && set_factor == 0)
                {
                        meta_command->meta_start_time = now +
                                command->rule->meta_max;
                }
                else
                {
                        const int new_factor = set_factor ? set_factor :
                                meta_command->factor *
                                command->rule->meta_factor;
                        const int duration = command->previously_on_blacklist ?
                                command->rule->dnsbl_duration :
                                command->duration;
                        if (duration * new_factor <
                                        command->rule->meta_max)
                        {
                                meta_command->factor = new_factor;
                                meta_command->meta_start_time = now +
                                        (long) duration * new_factor;
                        }
                        else
                        {
                                meta_command->factor = -1;
                                meta_command->meta_start_time = now +
                                        command->rule->meta_max;
                        }
                }
        }

        return meta_command->factor;
}

#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */

/* vim: set autowrite expandtab: */
