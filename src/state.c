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

#include <config.h>

#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#if HAVE_ALLOCA_H
#include <alloca.h>
#endif /* HAVE_ALLOCA_H */
#include <stdlib.h>
#include <limits.h>
#include <stdnoreturn.h>
#include <stddef.h>

#include "ndebug.h"
#include "logactiond.h"
#include "addresses.h"
#include "configfile.h"
#include "endqueue.h"
#include "logging.h"
#include "messages.h"
#include "misc.h"
#include "rules.h"
#include "state.h"

const char *saved_state = NULL;

pthread_t save_state_thread = 0;

static bool
move_state_file_to_backup(void)
{
        assert(saved_state);
        la_debug_func(saved_state);

        const size_t length = strlen(saved_state) + sizeof BAK_SUFFIX - 1;
        char *const backup_file_name = alloca(length + 1);

        if (snprintf(backup_file_name, length + 1, "%s%s", saved_state, BAK_SUFFIX) !=
                        length)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to create backup file name!");

        if (rename(saved_state, backup_file_name) == -1 && errno != ENOENT)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to create backup file!");

        return true;
}

static bool
recursively_save_state(FILE *const stream, const kw_tree_node_t *const node)
{
        if (node)
        {
                const la_command_t *const command = (la_command_t *)
                        node->payload;
                if (command->end_time != INT_MAX && !command->is_template)
                {
                        if (print_add_message(stream, command) < 0)
                                return false;
                }
                if (!recursively_save_state(stream, node->left))
                        return false;
                if (!recursively_save_state(stream, node->right))
                        return false;
        }

        return true;
}

void
save_state(bool verbose)
{
#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
        la_debug_func(NULL);
        assert(saved_state);

        if (!queue_length)
                return;

        if (log_verbose || verbose)
                la_log(LOG_INFO, "Dumping current state to \"%s\"",
                                saved_state);

        FILE *const stream = fopen(saved_state, "w");
        if (!stream)
                LOG_RETURN(, LOG_ERR, "Unable to open state file");

        const time_t now = xtime(NULL);
        char date_string[26];
        fprintf(stream, "# logactiond state %s\n", ctime_r(&now, date_string));

        xpthread_mutex_lock(&end_queue_mutex);

                if (!recursively_save_state(stream, adr_tree->root))
                        la_log_errno(LOG_ERR, "Failure to dump queue.");

        xpthread_mutex_unlock(&end_queue_mutex);

        if (fclose(stream) == EOF)
                la_log_errno(LOG_ERR, "Unable to close state file");
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
}

/* Return false on error. Non-existant state file is not considered an eror */

bool
restore_state(const bool create_backup_file)
{
        assert(saved_state);
        la_log(LOG_INFO, "Restoring state from \"%s\".", saved_state);

        FILE *const stream = fopen(saved_state, "r");
        if (!stream)
        {
                if (errno == ENOENT)
                        return true;
                else
                        LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to open state "
                                        "file \"%s\"", saved_state);
        }


        size_t linebuffer_size = 0;
        char *linebuffer = NULL;

        int line_no = 1;
        ssize_t num_read;
        int parse_result;

        while ((num_read = getline(&linebuffer,
                                        &linebuffer_size,stream)) != -1)
        {
                la_address_t address; la_rule_t *rule;
                time_t end_time; int factor;

                parse_result = parse_add_entry_message(linebuffer,
                                &address, &rule, &end_time, &factor);
                if (parse_result)
                        la_vdebug("adr: %s, rule: %s, end_time: %lu, factor: %u",
                                        address.text[0] ? address.text : "no address",
                                        rule ? rule->node.nodename : "no rule",
                                        end_time, factor);
                else
                        la_vdebug("parse_add_entry_message()==0");

                if (parse_result == -1)
                        break;
                else if (parse_result > 0)
                        trigger_manual_commands_for_rule(&address, rule,
                                        end_time, factor, NULL, true);

                line_no++;
        }

        // TODO: probably should be implemented differently instead of calling
        // empty_queue_pointers() from here (hint: start queue only after
        // restoring, don't create queue pointers when queue is not running)
        empty_queue_pointers();

        free(linebuffer);

        /* Return false to make sure state file is not overwritten in case of
         * an error */
        if (parse_result == -1)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Error parsing state file "
                                "\"%s\" at line %u!", saved_state,
                                line_no);

        if (!feof(stream))
                LOG_RETURN_ERRNO(false, LOG_ERR,
                                "Reading from state file \"%s\" failed",
                                saved_state);

        if (fclose(stream) == EOF)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to close state file");

        if (create_backup_file && !move_state_file_to_backup())
                LOG_RETURN_ERRNO(false, LOG_ERR, "Error creating backup file!");

        la_log(LOG_INFO, "Finished restoring state from \"%s\"", saved_state);
        return true;
}

noreturn static void *
periodically_save_state(void *const ptr)
{
        la_debug_func(NULL);

        for (;;)
        {
                sleep(DEFAULT_STATE_SAVE_PERIOD);

                if (shutdown_ongoing)
                {
                        la_debug("Shutting down end queue thread.");
                        pthread_exit(NULL);
                }

                save_state(false);
        }
        assert(false);
}

void
start_save_state_thread(void)
{
        la_debug_func(NULL);

        xpthread_create(&save_state_thread, NULL, periodically_save_state,
                        NULL, "save state");
}

/* vim: set autowrite expandtab: */
