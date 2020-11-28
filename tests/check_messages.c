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

pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

void
xpthread_mutex_lock(pthread_mutex_t *mutex)
{
}

void
xpthread_mutex_unlock(pthread_mutex_t *mutex)
{
}

int id_counter = 0;

time_t
xtime(time_t *tloc)
{
        return 1593272300;
}

/* Tests */

START_TEST (bla)
{
}
END_TEST

Suite *crypto_suite(void)
{
	Suite *s = suite_create("Messages");

        /* Core test case */
        TCase *tc_core = tcase_create("Core");
        tcase_add_test(tc_core, bla);
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
