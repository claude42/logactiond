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

#include <../src/commands.c>
#include <../src/commands.h>
#include <../src/addresses.h>
#include <../src/properties.h>
#include <../src/rules.h>
#include <../src/patterns.h>
#include <../src/configfile.h>
#include <../src/logactiond.h>
#include <../src/logging.h>
#include <../src/misc.h>

/* Mocks */

int log_level = LOG_DEBUG+2; /* by default log only stuff < log_level */
la_runtype_t run_type = LA_DAEMON_FOREGROUND;
bool log_verbose = true;
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

void
assert_rule_ffl(const la_rule_t *rule, const char *func, const char *file, int line)
{
}

void
assert_pattern_ffl(const la_pattern_t *pattern, const char *func,
                const char *file, int line)
{
}

la_config_t *la_config;

la_command_t *
find_end_command(const la_address_t *const address)
{
        return NULL;
}

void
enqueue_end_command(la_command_t *const end_command, const time_t manual_end_time)
{
}

bool
incr_counters_rule(la_rule_t *const rule)
{
        return true;
}

bool
incr_counters_pattern(la_pattern_t *const pattern)
{
        return true;
}

void
send_add_entry_message(const la_command_t *const command, const la_address_t *const address)
{
}

int id_counter;

/* Compare */

START_TEST (correct_address)
{
        la_rule_t rule = {
                .name = "Rulename"
        };

        la_command_t *template = create_template("Bla", &rule, "Foo begin", "Foo end", 100, LA_NEED_HOST_NO, true);

        ck_assert_str_eq(template->name, "Bla");
        ck_assert_int_eq(template->id, id_counter);
        ck_assert(template->is_template);
        ck_assert_str_eq(template->begin_string, "Foo begin");
        ck_assert(!template->begin_string_converted);
        ck_assert(is_list_empty(template->begin_properties));
        ck_assert_str_eq(template->end_string, "Foo end");
        ck_assert(!template->end_string_converted);
        ck_assert(is_list_empty(template->end_properties));
        ck_assert_ptr_eq(template->rule, &rule);
        ck_assert(!template->pattern);
        ck_assert(!template->pattern_properties);
        ck_assert(!template->address);
        ck_assert(template->need_host == LA_NEED_HOST_NO);
        ck_assert(template->quick_shutdown);
        ck_assert_int_eq(template->duration, 100);
        ck_assert_int_eq(template->factor, 1);
        ck_assert_str_eq(template->rule_name, rule.name);

        ck_assert(has_correct_address(template, NULL));

        la_address_t address;
        init_address(&address, "1.2.3.4");
        ck_assert(has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_IP4;
        ck_assert(has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_IP6;
        ck_assert(!has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_ANY;
        ck_assert(has_correct_address(template, &address));

        init_address(&address, "2a03:4000:23:8c::1");
        template->need_host = LA_NEED_HOST_NO;
        ck_assert(has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_IP4;
        ck_assert(!has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_IP6;
        ck_assert(has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_ANY;
        ck_assert(has_correct_address(template, &address));

        address.sa.ss_family = AF_UNSPEC;
        template->need_host = LA_NEED_HOST_NO;
        ck_assert(has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_IP4;
        ck_assert(!has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_IP6;
        ck_assert(!has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_ANY;
        ck_assert(!has_correct_address(template, &address));

        template->need_host = LA_NEED_HOST_NO;
        ck_assert(has_correct_address(template, NULL));

        template->need_host = LA_NEED_HOST_IP4;
        ck_assert(!has_correct_address(template, NULL));

        template->need_host = LA_NEED_HOST_IP6;
        ck_assert(!has_correct_address(template, NULL));

        template->need_host = LA_NEED_HOST_ANY;
        ck_assert(!has_correct_address(template, NULL));

}
END_TEST


Suite *commands_suite(void)
{
	Suite *s = suite_create("Commands");

        /* Core test case */
        TCase *tc_main = tcase_create("Main");
        tcase_add_test(tc_main, correct_address);
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
