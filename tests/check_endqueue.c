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

#include <syslog.h>
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>

#include <check.h>

#include <../src/endqueue.h>
#include <../src/endqueue.c>
#include <../src/state.h>
#include <../src/state.c>
#include <../src/rules.c>
#include <../src/commands.h>
#include <../src/commands.c>
#include <../src/addresses.h>
#include <../src/binarytree.h>
#include <../src/sources.h>
#include <../src/logging.h>
//#include <../src/commands.c>
/*#include <../src/properties.h>
#include <../src/rules.h>
#include <../src/patterns.h>
#include <../src/logactiond.h>
#include <../src/misc.h>*/

/* Mocks */

la_runtype_t run_type = LA_DAEMON_FOREGROUND;
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
atomic_bool shutdown_ongoing = false;
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
bool shutdown_ongoing = false;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
const char *const pidfile_name = PIDFILE;

static bool shutdown_good = false;
static char shutdown_msg[] = "Shutdown message not set";

int status_monitoring = 0;
la_config_t *la_config;
int id_counter = 0;
la_rule_t *rule;
la_source_group_t *sg;
la_command_t *template;
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
static int command_id;
static la_command_t *commands[100];


void
trigger_shutdown(int status, int saved_errno)
{
        la_log(LOG_INFO, "reached shutdown");
        if (!shutdown_good)
                ck_abort_msg(shutdown_msg);
}

void
assert_pattern_ffl(const la_pattern_t *pattern, const char *func, const char *file, int line) { }

void
free_pattern_list(kw_list_t *const list) { }

void
send_add_entry_message(const la_command_t *const command, const la_address_t *const address) { }

void
sync_entries(const char *const buffer, const char *const from) { }

void
stop_syncing(void) { }

void
trigger_reload(void) { }

void
dump_queue_status(const bool force) { }

void
dump_rules(void) { }

void
start_monitoring_thread(void) { }

void
pad(char *buffer, const size_t msg_len) { }


/* Trees */

static void
recursively_check_end_queue_adr(kw_tree_node_t *node)
{
        if (!node)
                return;

        recursively_check_end_queue_adr(node->left);
        commands[command_id++] = (la_command_t *) node->payload;
        recursively_check_end_queue_adr(node->right);
}

static void
recursively_check_end_queue_end_time(kw_tree_node_t *node)
{
        if (!node)
                return;

        recursively_check_end_queue_end_time(node->left);
        la_command_t *command = (la_command_t *) node->payload;
        la_debug("Found %u: %s, %lu", command_id, command->address->text, command->end_time);
        commands[command_id++] = command;
        recursively_check_end_queue_end_time(node->right);
}

static int
check_end_queues(void)
{
        command_id = 0;
        recursively_check_end_queue_end_time(end_time_tree->root);

        int i;
        if (command_id > 0)
        {
                for (i = 0; i < command_id - 1; i++)
                        ck_assert_int_le(commands[i]->end_time, commands[i+1]->end_time);
        }

        int command_id_1 = command_id;

        command_id = 0;
        recursively_check_end_queue_adr(adr_tree->root);

        if (command_id > 0)
        {
                for (i = 0; i < command_id - 1; i++)
                        ck_assert_int_le(adrcmp(commands[i]->address, commands[i+1]->address), 0);
        }

        ck_assert_int_eq(command_id, command_id_1);

        return command_id;
}

static void
init_stuff(void)
{
        log_level++;
        la_config = calloc(sizeof *la_config, 1);
        la_config->source_groups = create_list();
        la_config->ignore_addresses = create_list();
        la_log(LOG_INFO, "1: %u", la_config->source_groups);
        sg = create_source_group("Sourcegroup", "", "");
        rule = create_rule(true, "Rulename", sg, 3, 3, 3, 3, 0, 3, 3, 3, 0, "przf", NULL);
        add_tail(la_config->source_groups, (kw_node_t *) sg);
        la_log(LOG_INFO, "2: %u", la_config->source_groups);
        add_tail(sg->rules, (kw_node_t *) rule);

        template = create_template("Ruebezahl", rule, "true", "true", 1000,
                        LA_NEED_HOST_NO, true);
        add_tail(rule->begin_commands, (kw_node_t *) template);
        la_log(LOG_INFO, "List now: %u", list_length(rule->begin_commands));

        init_end_queue();
        la_log(LOG_INFO, "3: %u", la_config->source_groups);
}

START_TEST (trees)
{
        init_stuff();

        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("5.5.5.5"), ""), 2);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("1.1.1.1"), ""), 5);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("10.10.10.10"), ""), 3);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("7.7.7.7"), ""), 25);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("8.8.8.8"), ""), 20);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("20.20.20.20"), ""), 4);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("2.2.2.2"), ""), 1);

        ck_assert_int_eq(check_end_queues(), 7);
        ck_assert_int_eq(queue_length, 7);

        la_command_t *cmd = find_end_command(create_address("20.20.20.20"));
        ck_assert(cmd);
        ck_assert_str_eq(cmd->address->text, "20.20.20.20");
        remove_command_from_queues(cmd);
        ck_assert(!find_end_command(create_address("20.20.20.20")));
        ck_assert_int_eq(check_end_queues(), 6);
        ck_assert_int_eq(queue_length, 6);

        cmd = first_command_in_queue();
        ck_assert(cmd);
        ck_assert_str_eq(cmd->address->text, "2.2.2.2");
        remove_command_from_queues(cmd);
        ck_assert(!find_end_command(create_address("2.2.2.2")));
        ck_assert_int_eq(check_end_queues(), 5);
        ck_assert_int_eq(queue_length, 5);

        cmd = find_end_command(create_address("5.5.5.5"));
        ck_assert(cmd);
        ck_assert_str_eq(cmd->address->text, "5.5.5.5");
        remove_command_from_queues(cmd);
        ck_assert(!find_end_command(create_address("5.5.5.5")));
        ck_assert_int_eq(check_end_queues(), 4);
        ck_assert_int_eq(queue_length, 4);

        cmd = first_command_in_queue();
        ck_assert(cmd);
        la_log(LOG_INFO, "Found %s,%lu", cmd->address->text,cmd->end_time);
        ck_assert_str_eq(cmd->address->text, "10.10.10.10");
        cmd = next_command_in_queue(cmd);
        ck_assert(cmd);
        la_log(LOG_INFO, "Found %s,%lu", cmd->address->text,cmd->end_time);
        ck_assert_str_eq(cmd->address->text, "1.1.1.1");
        cmd = next_command_in_queue(cmd);
        ck_assert(cmd);
        la_log(LOG_INFO, "Found %s,%lu", cmd->address->text,cmd->end_time);
        ck_assert_str_eq(cmd->address->text, "8.8.8.8");
        cmd = next_command_in_queue(cmd);
        ck_assert(cmd);
        la_log(LOG_INFO, "Found %s,%lu", cmd->address->text,cmd->end_time);
        ck_assert_str_eq(cmd->address->text, "7.7.7.7");
        ck_assert(!next_command_in_queue(cmd));

        empty_end_queue();
        ck_assert_int_eq(check_end_queues(), 0);
        ck_assert_int_eq(queue_length, 0);
        ck_assert(is_empty(adr_tree));
        ck_assert(is_empty(end_time_tree));


}
END_TEST

START_TEST (null_elements)
{
        init_stuff();

        enqueue_end_command(template, INT_MAX);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("5.5.5.5"), ""), 2);

        la_command_t *cmd = find_end_command(create_address("5.5.5.5"));
        ck_assert_str_eq(cmd->address->text, "5.5.5.5");
}
END_TEST

START_TEST (state)
{
        init_stuff();
        la_log(LOG_INFO, "4: %u", la_config->source_groups);

        time_t now = xtime(NULL);

        la_command_t *c = create_manual_command_from_template(template,
                        create_address("5.5.5.5"), "");
        enqueue_end_command(c, now + 2);

        c = create_manual_command_from_template(template,
                        create_address("1.1.1.1"), "");
        enqueue_end_command(c, now + 5);

        c = create_manual_command_from_template(template,
                        create_address("10.10.10.10"), "");
        enqueue_end_command(c, now + 3);

        c = create_manual_command_from_template(template,
                        create_address("7.7.7.7"), "");
        enqueue_end_command(c, now + 25);

        c = create_manual_command_from_template(template,
                        create_address("8.8.8.8"), "");
        enqueue_end_command(c, now + 20);

        c = create_manual_command_from_template(template,
                        create_address("20.20.20.20"), "");
        enqueue_end_command(c, now + 4);

        c = create_manual_command_from_template(template,
                        create_address("2.2.2.2"), "");
        enqueue_end_command(c, now + 1);

        saved_state = "./testsavestate";
        save_state(true);

        empty_end_queue();
        ck_assert_int_eq(check_end_queues(), 0);
        ck_assert_int_eq(queue_length, 0);
        ck_assert(!find_end_command(create_address("1.1.1.1")));
        ck_assert(!find_end_command(create_address("2.2.2.2")));
        ck_assert(!find_end_command(create_address("5.5.5.5")));
        ck_assert(!find_end_command(create_address("7.7.7.7")));
        ck_assert(!find_end_command(create_address("8.8.8.8")));
        ck_assert(!find_end_command(create_address("10.10.10.10")));
        ck_assert(!find_end_command(create_address("20.20.20.20")));

        ck_assert(la_config->source_groups);
        assert_list(la_config->source_groups);

        ck_assert(restore_state(false));
        ck_assert_int_eq(queue_length, 7);
        ck_assert_int_eq(check_end_queues(), 7);
        ck_assert(find_end_command(create_address("1.1.1.1")));
        ck_assert(find_end_command(create_address("2.2.2.2")));
        ck_assert(find_end_command(create_address("5.5.5.5")));
        ck_assert(find_end_command(create_address("7.7.7.7")));
        ck_assert(find_end_command(create_address("8.8.8.8")));
        ck_assert(find_end_command(create_address("10.10.10.10")));
        ck_assert(find_end_command(create_address("20.20.20.20")));
}
END_TEST


Suite *commands_suite(void)
{
	Suite *s = suite_create("Commands");

        /* Core test case */
        TCase *tc_main = tcase_create("Main");
        tcase_add_test(tc_main, trees);
        tcase_add_test(tc_main, null_elements);
        tcase_add_test(tc_main, state);
        suite_add_tcase(s, tc_main);

        return s;
}

int
main(int argc, char *argv[])
{
        int number_failed = 0;
        Suite *s = commands_suite();
        SRunner *sr = srunner_create(s);

        srunner_run_all(sr, CK_NORMAL);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
 
/* vim: set autowrite expandtab: */
