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
#include "regex.h"

#include <check.h>

#include <../src/patterns.c>

#include <../src/patterns.h>
#include <../src/logactiond.h>
#include <../src/logging.h>
#include <../src/misc.h>
#include <../src/rules.h>
#include <../src/sources.h>
#include <../src/properties.h>

/* Mocks */

la_runtype_t run_type = LA_DAEMON_FOREGROUND;
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
        exit(shutdown_good ? 0 : 1);
}

void
assert_rule_ffl(const la_rule_t *rule, const char *func, const char *file, int line)
{
}

/* Tests */

START_TEST (check_patterns)
{
        struct tuple_s {
                char *prefix;
                char *service;
                char *pattern;
                int num;
                char *converted;
                bool has_host_token;
                char *tokens[3];
                char *repl[3];
                int numbraces[3];
                bool shutdown_good;
        };

        static struct tuple_s t[] = {
                {"prefix %service%: ", "food", "justastring", 0,
                        "prefix food: justastring", false, {}, {}, {}, false},
                {"^\\w{3} [ :[:digit:]]{11} [._[:alnum:]-]+ %service%(\\[[[:digit:]]+\\])?: ", "food", "Host: %host% %bla%", 0, "^\\w{3} [ :[:digit:]]{11} [._[:alnum:]-]+ food(\\[[[:digit:]]+\\])?: Host: ([.:[:xdigit:]]+) (.+)", true,
                        {"host", "bla", NULL}, {LA_HOST_TOKEN_REPL,
                                                       LA_TOKEN_REPL},
                        {LA_HOST_TOKEN_NUMBRACES, LA_TOKEN_NUMBRACES, 0},
                        false},
                {"", "", "fo%%%%o", 1, "fo%%o", false, {}, {}, {}, false},
                {"prefix", "food", "%host% %host%", 0, "doesn't matter", false, {}, {}, {}, true},
                {"prefix", "food", "((((((((((((((((((((()))))))))))))))))))))", 0, "doesn't matter", false, {}, {}, {}, true},
                {"prefix", "food", "bla\\", 0, "doesn't matter", false, {}, {}, {}, true}
        };

        la_source_group_t s = {
                .prefix = t[_i].prefix
        };

        la_rule_t r = {
                .source_group = &s,
                .service = t[_i].service
        };


        shutdown_good = t[_i].shutdown_good;
        la_pattern_t *p = create_pattern(t[_i].pattern, t[_i].num, &r);
        ck_assert(p);
        ck_assert_int_eq(p->num, t[_i].num);
        ck_assert_ptr_eq(p->rule, &r);
        ck_assert_str_eq(p->string, t[_i].converted);
        ck_assert((bool) p->host_property == t[_i].has_host_token);
        for (int j=0; j<=2; j++)
        {
                if (t[_i].tokens[j])
                {
                        la_property_t *pr =
                                get_property_from_property_list(p->properties,
                                                t[_i].tokens[j]);
                        ck_assert(pr);
                        ck_assert_str_eq(pr->replacement, t[_i].repl[j]);
                        ck_assert_int_eq(pr->replacement_braces, t[_i].numbraces[j]);

                }
        }



        free_pattern(p);
}
END_TEST

START_TEST (check_add_property)
{
        struct tuple_s {
                char *token;
                char *name;
                char *value;
                bool is_host_token;
        };

        static struct tuple_s t[] = {
                {"%host%", "host", "192.168.0.1", true},
                {"%bla%", "bla", "fasel", false}
        };

        la_source_group_t s = {
                .prefix = "foo"
        };

        la_rule_t r = {
                .source_group = &s,
                .service = "bar"
        };

        la_pattern_t *pat = create_pattern("ruebezahl", 0, &r);

        la_property_t *p1 = create_property_from_token(t[_i].token, _i, NULL);
        ck_assert(p1);
        assert_property(p1);
        string_copy(p1->value, MAX_PROP_SIZE, t[_i].value, 0, '\0');
        add_property(pat, p1);

        la_property_t *p2 = get_property_from_property_list(pat->properties, t[_i].name);
        ck_assert_ptr_eq(p1, p2);
        ck_assert_str_eq(p2->name, t[_i].name);
        ck_assert_str_eq(p2->value, t[_i].value);
        if (t[_i].is_host_token)
                ck_assert_ptr_eq(p2, pat->host_property);

        /* TODO: Edge cases missing */

}
END_TEST


Suite *patterns_suite(void)
{
	Suite *s = suite_create("patterns");

        /* Core test case */
        TCase *tc_core = tcase_create("Core");
        tcase_add_loop_test(tc_core, check_patterns, 0, 6);
        tcase_add_loop_test(tc_core, check_add_property, 0, 2);
        suite_add_tcase(s, tc_core);

        return s;
}

int
main(int argc, char *argv[])
{
        int number_failed = 0;
        Suite *s = patterns_suite();
        SRunner *sr = srunner_create(s);

        srunner_run_all(sr, CK_NORMAL);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
 
/* vim: set autowrite expandtab: */
