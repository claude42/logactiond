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

#define _GNU_SOURCE
#include <syslog.h>
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
#include <stdbool.h>
#include <stdio.h>
/*#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <alloca.h>
#include <signal.h>*/

#include <check.h>

//#include <../src/properties.h>
#include <../src/properties.c>
#include <../src/logactiond.h>
#include <../src/logging.h>
#include <../src/misc.h>
#include <../src/rules.h>

/* Mocks */

int log_level = LOG_DEBUG+2; /* by default log only stuff < log_level */
la_runtype_t run_type = LA_DAEMON_FOREGROUND;
bool log_verbose = true;
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
atomic_bool shutdown_ongoing = false;
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
bool shutdown_ongoing = false;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
const char *const pidfile_name = "/tmp/logactiond.pid";

static bool shutdown_good = false;
static char shutdown_msg[] = "Shutdown message not set";

void
trigger_shutdown(int status, int saved_errno)
{
        ck_assert_msg(shutdown_good, shutdown_msg);
        exit(1);
}

/* Tests */

START_TEST (check_token_length)
{
        struct tuple_s {
                char *token;
                size_t ret;
        };

        static struct tuple_s t[] = {
                {"%%", 2},
                {"%a%", 3},
                {"%bla%", 5},
        };

        ck_assert_int_eq(token_length(t[_i].token),  t[_i].ret);
}
END_TEST

START_TEST (check_token_length_no_end)
{
        shutdown_good = true;
        token_length("%neverending");
        ck_abort_msg("token_length(\"%neverending\") returned");
}
END_TEST

START_TEST (check_properties)
{
        kw_list_t *l1 = xcreate_list();
        la_property_t *p1 = create_property_from_config("fOo", "bAr");
        ck_assert(p1);
        ck_assert_str_eq(p1->name, "foo");
        ck_assert_str_eq(p1->value, "bAr");
        ck_assert(!p1->is_host_property);
        ck_assert(!p1->replacement);
        add_tail(l1, (kw_node_t *) p1);

        la_property_t *p2 = create_property_from_token("%HOST% blafasel", 42, NULL);
        ck_assert(p2);
        ck_assert_str_eq(p2->name, "host");
        ck_assert_int_eq(p2->length, 6);
        ck_assert_str_eq(p2->value, "");
        ck_assert(p2->is_host_property);
        ck_assert_str_eq(p2->replacement, LA_HOST_TOKEN_REPL);
        ck_assert_int_eq(p2->replacement_braces, LA_HOST_TOKEN_NUMBRACES);
        ck_assert_int_eq(p2->pos, 42);

        add_tail(l1, (kw_node_t *)  p2);

        la_rule_t r = {
                .service = "postfix/(submission/)?smtpd"
        };
        la_property_t *p3 = create_property_from_token("%" LA_SERVICE_TOKEN "%", 111, &r);
        add_tail(l1, (kw_node_t *)  p3);

        la_property_t *p33= create_property_from_token("%BLUBBER%", 4711, &r);
        ck_assert(p33);
        ck_assert_str_eq(p33->name, "blubber");
        ck_assert_int_eq(p33->length, 9);
        ck_assert_str_eq(p33->value, "");
        ck_assert(!p33->is_host_property);
        ck_assert_str_eq(p33->replacement, LA_TOKEN_REPL);
        ck_assert_int_eq(p33->replacement_braces, LA_TOKEN_NUMBRACES);
        ck_assert_int_eq(p33->pos, 4711);


        ck_assert(!create_property_from_token("%% blafasel", 42, NULL));

        kw_list_t *l2 = dup_property_list(l1);
        ck_assert_int_eq(list_length(l2), 3);

        ck_assert_str_eq(get_value_from_property_list(l2, "foo"), "bAr");

        la_property_t *p4 = get_property_from_property_list(l2, LA_SERVICE_TOKEN);

        ck_assert(p4);
        ck_assert_str_eq(p4->name, LA_SERVICE_TOKEN);
        ck_assert_int_eq(p4->length, sizeof LA_SERVICE_TOKEN - 1 + 2);
        ck_assert_str_eq(p4->value, "");
        ck_assert(!p4->is_host_property);
        ck_assert_str_eq(p4->replacement, r.service);
        ck_assert_int_eq(p4->replacement_braces, 1);
        ck_assert_int_eq(p4->pos, 111);

        la_property_t *p5 = duplicate_property(p4);
        ck_assert_str_eq(p5->name, p4->name);
        ck_assert(p5->is_host_property == p4->is_host_property);
        ck_assert_str_eq(p5->value, p4->value);
        ck_assert_str_eq(p5->replacement, p4->replacement);
        ck_assert_int_eq(p5->replacement_braces, p4->replacement_braces);
        ck_assert_int_eq(p5->pos, p4->pos);
        ck_assert_int_eq(p5->length, p4->length);
        ck_assert_int_eq(p5->subexpression, p4->subexpression);

        free_property_list(l1);
        free_property_list(l2);
        free_property(p5);

}
END_TEST

START_TEST (check_copy_str_and_tolower)
{
        char dest[255];
        ck_assert_int_eq(copy_str_and_tolower(dest, "Rubezahl1%Rumpelstilzchen", '%'), 9);
        ck_assert_str_eq(dest, "rubezahl1");
        ck_assert_int_eq(copy_str_and_tolower(dest, "", 0), 0);
        ck_assert_str_eq(dest, "");
        ck_assert_int_eq(copy_str_and_tolower(dest, "Rubezahl2", 0), 9);



        ck_assert_str_eq(dest, "rubezahl2");
        ck_assert_int_eq(copy_str_and_tolower(dest, "%rumpelstilzchen", '%'), 0);
        ck_assert_str_eq(dest, "");
}
END_TEST

START_TEST (check_copy_str_and_tolower2)
{
        char dest[255];
        shutdown_good = true;
        ck_assert_int_eq(copy_str_and_tolower(dest,
                                "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                                "12345678901234567890123456789012345678901234567"
                                "overflow", 0), -2);
        ck_abort_msg("copy_str_and_tolower did not detect oversized string");
}
END_TEST

START_TEST (check_copy_str_and_tolower3)
{
        char dest[255];
        shutdown_good = true;
        ck_assert_int_eq(copy_str_and_tolower(dest, "!$%&/", 6), -2);
        ck_abort_msg("copy_str_and_tolower did not detect non-alphanumeric characters");
}
END_TEST

START_TEST (check_copy_str_and_tolower4)
{
        char dest[255];
        shutdown_good = true;
        ck_assert_int_eq(copy_str_and_tolower(dest, "Rübezahl", 6), -2);
        ck_abort_msg("copy_str_and_tolower did not detect non-alphanumeric characters");
}
END_TEST

START_TEST (check_count_open_braces)
{
        ck_assert_int_eq(count_open_braces("(())"), 2);
        ck_assert_int_eq(count_open_braces("\\(()"), 1);
        ck_assert_int_eq(count_open_braces("blafasel"), 0);
        ck_assert_int_eq(count_open_braces(""), 0);
}
END_TEST

START_TEST (check_count_open_braces2)
{
        shutdown_good = true;
        count_open_braces("\\");
        ck_abort_msg("count_open_braces did not fail on \\\\0");
}
END_TEST

Suite *properties_suite(void)
{
	Suite *s = suite_create("Properties");

        /* Core test case */
        TCase *tc_core = tcase_create("Core");
        tcase_add_loop_test(tc_core, check_token_length, 0, 3);
        tcase_add_exit_test(tc_core, check_token_length_no_end, 1);
        tcase_add_test(tc_core, check_properties);
        suite_add_tcase(s, tc_core);

        /* Copy str test case */
        TCase *tc_copy_str = tcase_create("Copystr");
        tcase_add_test(tc_copy_str, check_copy_str_and_tolower);
        tcase_add_exit_test(tc_copy_str, check_copy_str_and_tolower2, 1);
        tcase_add_exit_test(tc_copy_str, check_copy_str_and_tolower3, 1);
        tcase_add_exit_test(tc_copy_str, check_copy_str_and_tolower4, 1);
        suite_add_tcase(s, tc_copy_str);

        /* Count braces test case */
        TCase *tc_count_braces = tcase_create("Countbraces");
        tcase_add_test(tc_count_braces, check_count_open_braces);
        tcase_add_exit_test(tc_count_braces, check_count_open_braces2, 1);
        suite_add_tcase(s, tc_count_braces);

        return s;
}

int
main(int argc, char *argv[])
{
        int number_failed = 0;
        Suite *s = properties_suite();
        SRunner *sr = srunner_create(s);

        srunner_run_all(sr, CK_NORMAL);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
 
/* vim: set autowrite expandtab: */
