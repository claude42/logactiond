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
#include <alloca.h>
#include <pthread.h>

#include <check.h>

#include <../src/messages.c>
#include <../src/addresses.h>
#include <../src/logactiond.h>
#include <../src/logging.h>
#include <../src/misc.h>

/* Mocks */

la_runtype_t run_type = LA_DAEMON_FOREGROUND;
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
atomic_bool shutdown_ongoing = false;
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
bool shutdown_ongoing = false;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
const char *const pidfile_name = PIDFILE;

char *method_called = NULL;
la_address_t *test_address = NULL;
int status_monitoring = 0;

void
trigger_manual_commands_for_rule(const la_address_t *const address,
                const  la_rule_t *const rule, const time_t end_time,
                const int factor, const char *const from,
                const bool suppress_logging)
{
}

int
remove_and_trigger(la_address_t *const address)
{
        test_address = dup_address(address);
        method_called = "remove_and_trigger";
        return 0;
}

void
empty_end_queue(void)
{
        method_called = "empty_end_queue";
}

void
trigger_reload(void)
{
        method_called = "trigger_reload";
}

void
trigger_shutdown(int status, int saved_errno)
{
        method_called = "trigger_shutdown";
}

void
save_state(bool verbose)
{
        method_called = "save_state";
}

void
start_monitoring_thread(void)
{
        method_called = "start_monitoring_thread";
}

void
dump_queue_status(const bool force)
{
        method_called = "dump_queue_status";
}

void
dump_rules(void)
{
        if (!strcmp(method_called, "dump_queue_status"))
                method_called = "dump_queue_status, dump_rules";
}

pthread_mutex_t config_mutex;

void
pad(char *buffer, const size_t msg_len)
{
}

la_rule_t *
find_rule(const char *const rule_name)
{
        if (!strcmp(rule_name, "existingrule"))
                return (la_rule_t *) 1;
        else
                return NULL;
}

void
sync_entries(const char *const buffer, const char *const from)
{
        method_called = "sync_entries";
}

void
stop_syncing(void)
{
        method_called = "stop_syncing";
}

void
reset_counts(void)
{
        method_called = "reset_counts";
}

/* Tests */

START_TEST (parse_add_message)
{
        la_address_t address;
        la_rule_t *rule;
        time_t end_time;
        int factor;

        /* empty lines */
        ck_assert_int_eq(parse_add_entry_message("", &address, &rule, NULL,
                                NULL), 0);
        ck_assert_int_eq(parse_add_entry_message("\t", &address, &rule, NULL,
                                NULL), 0);
        ck_assert_int_eq(parse_add_entry_message("# comment", &address, &rule, NULL,
                                NULL), 0);
        ck_assert_int_eq(parse_add_entry_message("      # comment", &address, &rule, NULL,
                                NULL), 0);
        ck_assert_int_eq(parse_add_entry_message("\n", &address, &rule, NULL,
                                NULL), 0);
        ck_assert_int_eq(parse_add_entry_message("  \n", &address, &rule, NULL,
                                NULL), 0);

        /* acceptable commands */
        ck_assert_int_eq(parse_add_entry_message(
                                "0+1.2.3.4,existingrule,1234567,16", &address,
                                &rule, NULL, NULL), 1);
        ck_assert_str_eq(address.text, "1.2.3.4");

        ck_assert_int_eq(parse_add_entry_message(
                                "0+1.2.3.4,existingrule,1234567,16", &address,
                                &rule, &end_time, &factor), 1);
        ck_assert_str_eq(address.text, "1.2.3.4");
        ck_assert_int_eq(end_time, 1234567);
        ck_assert_int_eq(factor, 16);

        ck_assert_int_eq(parse_add_entry_message(
                                "0+fe80::e4e3:55ff:fe76:48e4,existingrule,1234567,16", &address,
                                &rule, &end_time, &factor), 1);
        ck_assert_str_eq(address.text, "fe80::e4e3:55ff:fe76:48e4");
        ck_assert_int_eq(end_time, 1234567);
        ck_assert_int_eq(factor, 16);

        ck_assert_int_eq(parse_add_entry_message(
                                "0+1.2.3.4,existingrule", &address,
                                &rule, &end_time, &factor), 1);
        ck_assert_str_eq(address.text, "1.2.3.4");
        ck_assert_int_eq(end_time, 0);
        ck_assert_int_eq(factor, 0);

        /* errors */

        ck_assert_int_eq(parse_add_entry_message( "0+1.2.3.4,nonexisting",
                                &address, &rule, &end_time, &factor), -1);

        ck_assert_int_eq(parse_add_entry_message( "0+illegal,nonexisting",
                                &address, &rule, &end_time, &factor), -1);

        ck_assert_int_eq(parse_add_entry_message(
                                "X+1.2.3.4,existingrule,1234567,16", &address,
                                &rule, NULL, NULL), -1);
        ck_assert_int_eq(parse_add_entry_message(
                                "0X1.2.3.4,existingrule,1234567,16", &address,
                                &rule, NULL, NULL), -1);
        ck_assert_int_eq(parse_add_entry_message( "0+1.2.3.4", &address, &rule,
                                NULL, NULL), -1);
}
END_TEST

START_TEST (parse_xxx_message)
{
        /* CMD_DEL */
        method_called = NULL;
        test_address = NULL;
        parse_message_trigger_command("0-1.2.3.4", "9.9.9.9");
        ck_assert_str_eq(method_called, "remove_and_trigger");
        ck_assert_str_eq(test_address->text, "1.2.3.4");

        method_called = NULL;
        test_address = NULL;
        parse_message_trigger_command("0-illegal", "9.9.9.9");
        ck_assert_ptr_eq(method_called, NULL);
        ck_assert_ptr_eq(test_address, NULL);

        /* CMD_FLUSH */
        method_called = NULL;
        parse_message_trigger_command("0F", "9.9.9.9");
        ck_assert_str_eq(method_called, "empty_end_queue");

        /* CMD_RELOAD */
        method_called = NULL;
        parse_message_trigger_command("0R", "9.9.9.9");
        ck_assert_str_eq(method_called, "trigger_reload");

        /* CMD_SHUTDOWN */
        method_called = NULL;
        parse_message_trigger_command("0S", "9.9.9.9");
        ck_assert_str_eq(method_called, "trigger_shutdown");

        /* CMD_SAVE_STATE */
        method_called = NULL;
        parse_message_trigger_command("0>", "9.9.9.9");
        ck_assert_str_eq(method_called, "save_state");

        /* CMD_CHANGE_LOG_LEVEL */
        log_level = 7;
        parse_message_trigger_command("0L5", "9.9.9.9");
        ck_assert_int_eq(log_level, 5);
        parse_message_trigger_command("0LX", "9.9.9.9");
        ck_assert_int_eq(log_level, 5);
        parse_message_trigger_command("0L10", "9.9.9.9");
        ck_assert_int_eq(log_level, 5);
        parse_message_trigger_command("0L", "9.9.9.9");
        ck_assert_int_eq(log_level, 5);

        /* CMD_RESET_COUNTS */
        method_called = NULL;
        parse_message_trigger_command("00", "9.9.9.9");
        ck_assert_str_eq(method_called, "reset_counts");

        /* CMD_SYNC */
        method_called = NULL;
        parse_message_trigger_command("0X", "9.9.9.9");
        ck_assert_str_eq(method_called, "sync_entries");

        /* CMD_STOPSYNC */
        method_called = NULL;
        parse_message_trigger_command("0x", "9.9.9.9");
        ck_assert_str_eq(method_called, "stop_syncing");

        /* CMD_DUMP_STATUS */
        method_called = NULL;
        parse_message_trigger_command("0D", "9.9.9.9");
        ck_assert_str_eq(method_called, "dump_queue_status, dump_rules");

        /* CMD_ENABLE_RULE */
        /* CMD_DISABLE_RULE */
        /* TODO! */

        /* CMD_UPDATE_STATUS_MONITORING */
        status_monitoring = 0;
        method_called = NULL;
        parse_message_trigger_command("0M1", "9.9.9.9");
        ck_assert_int_eq(status_monitoring, 1);
        ck_assert_str_eq(method_called, "start_monitoring_thread");
        method_called = NULL;
        parse_message_trigger_command("0M2", "9.9.9.9");
        ck_assert_int_eq(status_monitoring, 2);
        ck_assert_ptr_eq(method_called, NULL);
        method_called = NULL;
        parse_message_trigger_command("0M0", "9.9.9.9");
        ck_assert_int_eq(status_monitoring, 0);
        ck_assert_ptr_eq(method_called, NULL);

        /* Errors */

        method_called = NULL;
        parse_message_trigger_command("XF", "9.9.9.9");
        ck_assert_ptr_eq(method_called, NULL);
        method_called = NULL;
        parse_message_trigger_command("0ä", "9.9.9.9");
        ck_assert_ptr_eq(method_called, NULL);

}

END_TEST
START_TEST (init_message)
{
        char *const m = alloca(TOTAL_MSG_LEN);

        ck_assert(init_add_message(m, "1.2.3.4", "sshd", NULL, NULL));
        ck_assert_str_eq(m, "0+1.2.3.4,sshd");

        ck_assert(init_add_message(m, "fe80::e4e3:55ff:fe76:48e4", "dovecot",
                                "12345", "16"));
        ck_assert_str_eq(m, "0+fe80::e4e3:55ff:fe76:48e4,dovecot,12345,16");

        ck_assert(init_del_message(m, "1.2.3.4"));
        ck_assert_str_eq(m, "0-1.2.3.4");

        ck_assert(init_flush_message(m));
        ck_assert_str_eq(m, "0F");

        ck_assert(init_reload_message(m));
        ck_assert_str_eq(m, "0R");

        ck_assert(init_shutdown_message(m));
        ck_assert_str_eq(m, "0S");

        ck_assert(init_save_message(m));
        ck_assert_str_eq(m, "0>");

        ck_assert(init_log_level_message(m, 1));
        ck_assert_str_eq(m, "0L1");

        ck_assert(init_status_monitoring_message(m, 2));
        ck_assert_str_eq(m, "0M2");

        ck_assert(init_reset_counts_message(m));
        ck_assert_str_eq(m, "00");

        ck_assert(init_sync_message(m, NULL));
        ck_assert_str_eq(m, "0X");

        ck_assert(init_sync_message(m, "foo.bar.com"));
        ck_assert_str_eq(m, "0Xfoo.bar.com");

        ck_assert(init_stopsync_message(m));
        ck_assert_str_eq(m, "0x");

        ck_assert(init_dump_message(m));
        ck_assert_str_eq(m, "0D");

        ck_assert(init_enable_message(m, "sshd"));
        ck_assert_str_eq(m, "0Ysshd");

        ck_assert(init_disable_message(m, "postfix-sasl"));
        ck_assert_str_eq(m, "0Npostfix-sasl");

}
END_TEST

Suite *crypto_suite(void)
{
	Suite *s = suite_create("Messages");

        /* Core test case */
        TCase *tc_core = tcase_create("Core");
        tcase_add_test(tc_core, parse_add_message);
        tcase_add_test(tc_core, parse_xxx_message);
        tcase_add_test(tc_core, init_message);
        suite_add_tcase(s, tc_core);

        return s;
}

int
main(int argc, char *argv[])
{
        int number_failed = 0;
        Suite *s = crypto_suite();
        SRunner *sr = srunner_create(s);

        srunner_run_all(sr, CK_NORMAL);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
 
/* vim: set autowrite expandtab: */
