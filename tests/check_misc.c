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
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <alloca.h>
#include <signal.h>
#include <sys/stat.h>

#include <check.h>

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
const char *const pidfile_name = "/tmp/logactiond.pid";

static bool shutdown_good = false;
static char shutdown_msg[] = "Shutdown message not set";

void
trigger_shutdown(int status, int saved_errno)
{
        if (!shutdown_good)
                ck_abort_msg(shutdown_msg);
}

/* Tests */

#define PIDFILE_TEST "/tmp/123xyz_test_pid"

START_TEST (pid)
{
        remove(PIDFILE_TEST);
        create_pidfile(PIDFILE_TEST);

        FILE *const stream = fopen(PIDFILE_TEST, "r");
        ck_assert(stream);
        int pid;
        ck_assert(fscanf(stream, "%u", &pid) ==  1);
        ck_assert_int_eq(pid, getpid());

        ck_assert(check_pidfile(PIDFILE_TEST));

        ck_assert(remove_pidfile(PIDFILE_TEST));
        ck_assert(!fopen(PIDFILE_TEST, "r"));

        // must not fail on ENOENT
        ck_assert(remove_pidfile(PIDFILE_TEST));

        // must return 0 on ENOENT
        ck_assert(!check_pidfile(PIDFILE_TEST));
}
END_TEST

START_TEST (pid_exit)
{
        create_pidfile(PIDFILE_TEST);
        chmod(PIDFILE_TEST, 0);
        check_pidfile(PIDFILE_TEST);
}
END_TEST

static void *thread_func(void *const ptr)
{
        sleep(2);
        pthread_exit(0);
}

/* Threads */

START_TEST (check_create_thread)

{
        pthread_t t;
        xpthread_create(&t, NULL, thread_func, NULL, "testname");
        char *n = alloca(16);
        ck_assert(!pthread_getname_np(t, n, 16));
        ck_assert_str_eq(n, "testname");

}
END_TEST

/* Strings */

START_TEST (check_concat)
{
        static const char *a[] = {"Foo", "", NULL, "Foo", "", NULL, "Foo", ""};
        static const char *b[] = {"Bar", "Bar", "Bar", "", "", "", NULL, NULL};
        static const char *c[] = {"FooBar", "Bar", "Bar", "Foo", "", "", "Foo", ""};

        ck_assert_str_eq(concat(a[_i], b[_i]), c[_i]);
}
END_TEST

START_TEST (check_concat_null)
{
        ck_assert(!concat(NULL, NULL));
}
END_TEST

START_TEST (check_string_copy)
{
        struct tuple_s {
                int dest_size;
                int length;
                char delim;
                char *result;
                int ret;
        };

        static struct tuple_s t[] = {
                {10, 0, '\0', "blafasel", 8},
                {5, 0, '\0', "blaf", -1},
                {10, 5, '\0', "blafa", 5},
                {3, 5, '\0', "bl", -1},
                {10, 10, '\0', "blafasel", 8},
                {10, 0, 'f', "bla", 3},
                {0, 0, '\0', "", -1},
                {0, 0, '\0', "blafasel", -1},
        };
        static char s[10];

        ck_assert_int_eq(string_copy(s, t[_i].dest_size, "blafasel",
                                t[_i].length, t[_i].delim), t[_i].ret);
        ck_assert_str_eq(s, t[_i].result);
}
END_TEST

START_TEST (check_strendcmp_match)
{
        struct tuple_s {
                char *string;
                char *suffix;
        };

        static struct tuple_s t[] = {
                {"/foo/bar/baz", "baz"},
                {"same", "same"},
                {"something", ""},
                {"", ""},
                {NULL, NULL}
        };

        ck_assert(!strendcmp(t[_i].string, t[_i].suffix));
}
END_TEST

START_TEST (check_strendcmp_dontmatch)
{
        struct tuple_s {
                char *string;
                char *suffix;
        };

        static struct tuple_s t[] = {
                {"/foo/bar/baz", "aaa"},
                {"short", "longshort"},
                {NULL, "baz"},
                {"baz", NULL}
        };

        ck_assert(strendcmp(t[_i].string, t[_i].suffix));
}
END_TEST

START_TEST (check_realloc_buffer)
{
        size_t dst_len = 100;
        char *dst = xmalloc(dst_len);
        char *dst_ptr = dst + 10;

        realloc_buffer(&dst, &dst_ptr, &dst_len, 50);
        ck_assert_int_eq(dst_len, 100);
        ck_assert(dst_ptr = dst+10);

        realloc_buffer(&dst, &dst_ptr, &dst_len, 140);
        ck_assert_int_ge(dst_len, 150);
        ck_assert(dst_ptr = dst+10);

        realloc_buffer(&dst, &dst_ptr, &dst_len, 0);
        ck_assert_int_ge(dst_len, 150);
        ck_assert(dst_ptr = dst+10);
}
END_TEST


Suite *misc_suite(void)
{
	Suite *s = suite_create("Misc");

        /* Core test case */
        TCase *tc_pid = tcase_create("PID");
        tcase_add_test(tc_pid, pid);
        tcase_add_exit_test(tc_pid, pid_exit, 1);
        suite_add_tcase(s, tc_pid);

        TCase *tc_threads = tcase_create("Threads");
        tcase_add_test(tc_threads, check_create_thread);
        suite_add_tcase(s, tc_threads);

        TCase *tc_strings = tcase_create("Strings");
        tcase_add_loop_test(tc_strings, check_concat, 0, 8);
        tcase_add_test(tc_strings, check_concat_null);
        tcase_add_loop_test(tc_strings, check_string_copy, 0, 7);
        tcase_add_loop_test(tc_strings, check_strendcmp_match, 0, 5);
        tcase_add_loop_test(tc_strings, check_strendcmp_dontmatch, 0, 5);
        tcase_add_test(tc_strings, check_realloc_buffer);
        suite_add_tcase(s, tc_strings);

        return s;
}

int
main(int argc, char *argv[])
{
        int number_failed = 0;
        Suite *s = misc_suite();
        SRunner *sr = srunner_create(s);

        srunner_run_all(sr, CK_NORMAL);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
 
/* vim: set autowrite expandtab: */
