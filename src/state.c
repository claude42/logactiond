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

#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>

#include "logactiond.h"

pthread_t save_state_thread = 0;

static bool
move_state_file_to_backup(const char *state_file_name)
{
        assert(state_file_name);
        la_debug("move_state_file_to_backup(%s)", state_file_name);

        const int length = strlen(state_file_name) + sizeof(BAK_SUFFIX) - 1;
        char *backup_file_name = alloca(length + 1);

        if (snprintf(backup_file_name, length + 1, "%s%s", state_file_name, ".bak") !=
                        length)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to create backup file name!");

        if (rename(state_file_name, backup_file_name) == -1 && errno != ENOENT)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to create backup file!");

        return true;
}

void
save_state(const char *state_file_name)
{
        assert(state_file_name);
        la_debug("save_state(%s)", state_file_name);

        save_queue_state(state_file_name);
}

bool
restore_state(const char *state_file_name, const bool create_backup_file)
{
        assert(state_file_name);
        la_debug("restore_state(%s)", state_file_name);

        if (create_backup_file && !move_state_file_to_backup(state_file_name))
                LOG_RETURN_ERRNO(false, LOG_ERR, "Error creating backup file!");

        FILE *stream = fopen(state_file_name, "r");
        if (!stream)
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to open state file \"%s\"",
                                state_file_name);

        la_log_verbose(LOG_INFO, "Restoring state from \"%s\"", state_file_name);

        size_t linebuffer_size = DEFAULT_LINEBUFFER_SIZE*sizeof(char);
        char *linebuffer = alloca(linebuffer_size);

        xpthread_mutex_lock(&config_mutex);

                int line_no = 1;
                ssize_t num_read;

                while ((num_read = getline(&linebuffer,
                                                &linebuffer_size,stream)) != -1)
                {
                        la_address_t *address; la_rule_t *rule;
                        time_t end_time; int factor;

                        const int r = parse_add_entry_message(linebuffer,
                                        &address, &rule, &end_time, &factor);
                        la_vdebug("adr: %s, rule: %s, end_time: %u, factor: %u",
                                        address ? address->text : "no address",
                                        rule ? rule->name : "no rule", end_time, factor);
                        if (r == -1)
                                /* Don't override state file in case of error */
                                LOG_RETURN_ERRNO(false, LOG_ERR,
                                                "Error parsing state file "
                                                "\"%s\" at line %u!",
                                                state_file_name, line_no);
                        else if (r > 0)
                                trigger_manual_commands_for_rule(address, rule,
                                                end_time, factor, NULL, true);

                        free_address(address);
                        line_no++;
                }

                if (!feof(stream))
                        /* Don't override state file in case of error */
                        LOG_RETURN_ERRNO(false, LOG_ERR,
                                        "Reading from state file \"%s\" failed",
                                        state_file_name);

        xpthread_mutex_unlock(&config_mutex);

        if (fclose(stream) == EOF)
                /* Don't override state file in case of error */
                LOG_RETURN_ERRNO(false, LOG_ERR, "Unable to close state file");

        return true;
}

static void *
periodically_save_state(void *ptr)
{
        la_debug("periodically_save_state()");

        for (;;)
        {
                xnanosleep(DEFAULT_STATE_SAVE_PERIOD, 0);

                if (shutdown_ongoing)
                {
                        la_debug("Shutting down end queue thread.");
                        pthread_exit(NULL);
                }

                save_state((char *) ptr);
        }
}

void
start_save_state_thread(char *state_file_name)
{
        la_debug("start_save_state_thread()");

        xpthread_create(&save_state_thread, NULL, periodically_save_state,
                        state_file_name, "save state");
}


/* vim: set autowrite expandtab: */
