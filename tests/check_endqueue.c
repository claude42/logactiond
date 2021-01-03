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
#include <../src/commands.h>
#include <../src/commands.c>
#include <../src/addresses.h>
#include <../src/binarytree.h>
/*#include <../src/properties.h>
#include <../src/rules.h>
#include <../src/patterns.h>
#include <../src/configfile.h>
#include <../src/logactiond.h>
#include <../src/logging.h>
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

void
trigger_shutdown(int status, int saved_errno)
{
        la_log(LOG_INFO, "reached shutdown");
        if (!shutdown_good)
                ck_abort_msg(shutdown_msg);
}

/*void
assert_command_ffl(const la_command_t *command, const char *func, const char *file, int line)
{
}*/

void
assert_rule_ffl(const la_rule_t *rule, const char *func, const char *file, int line)
{
}

void
assert_pattern_ffl(const la_pattern_t *pattern, const char *func, const char *file, int line)
{
}

/*void
assert_property_ffl(const la_property_t *property, const char *func, const char *file, int line)
{
}*/

la_rule_t *
find_rule(const char *const rule_name)
{
        return NULL;
}

la_config_t *la_config;

/*void
trigger_end_command(const la_command_t *const command, const bool suppress_logging)
{
}*/

/*void
free_command(la_command_t *const command)
{
}*/

void
send_add_entry_message(const la_command_t *const command, const la_address_t *const address)
{
}

pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Trees */

static int command_id;
static la_command_t *commands[100];

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
        for (i = 0; i < command_id - 1; i++)
        {
                la_log(LOG_INFO,"commands[%u]=%s,%lu\n", i,
                                commands[i]->address->text,
                                commands[i]->end_time);
                ck_assert_int_le(commands[i]->end_time, commands[i+1]->end_time);
        }
        la_log(LOG_INFO,"commands[%u]=%s,%lu\n", i, commands[i]->address->text,
                        commands[i]->end_time);

        int command_id_1 = command_id;

        command_id = 0;
        recursively_check_end_queue_adr(adr_tree->root);

        for (i = 0; i < command_id - 1; i++)
        {
                la_log(LOG_INFO,"commands[%u]=%s,%lu\n", i,
                                commands[i]->address->text,
                                commands[i]->end_time);
                ck_assert_int_le(adrcmp(commands[i]->address, commands[i+1]->address), 0);
        }
        la_log(LOG_INFO,"commands[%u]=%s,%lu\n", i, commands[i]->address->text,
                        commands[i]->end_time);

        ck_assert_int_eq(command_id, command_id_1);

        return command_id;
}

START_TEST (trees)
{
        la_rule_t rule = { .name = "Rulename" };

        la_command_t *template = create_template("Ruebezahl", &rule, "", "", 1,
                        LA_NEED_HOST_NO, true);

        init_end_queue();

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
        //ck_assert(!find_end_command(create_address("5.5.5.5")));
        remove_command_from_queues(cmd);
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
        init_end_queue();

        la_rule_t rule = { .name = "Rulename" };

        la_command_t *template = create_template("Ruebezahl", &rule, "", "", 1,
                        LA_NEED_HOST_NO, true);

        enqueue_end_command(template, INT_MAX);
        enqueue_end_command(create_manual_command_from_template(template,
                                create_address("5.5.5.5"), ""), 2);

        la_command_t *cmd = find_end_command(create_address("5.5.5.5"));
        ck_assert_str_eq(cmd->address->text, "5.5.5.5");
}
END_TEST



Suite *commands_suite(void)
{
	Suite *s = suite_create("Commands");

        /* Core test case */
        TCase *tc_main = tcase_create("Main");
        tcase_add_test(tc_main, trees);
        tcase_add_test(tc_main, null_elements);
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
