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

#include <check.h>

#include <../src/crypto.c>
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

/* Tests */

START_TEST (check_encrypt_decrypt)
{
#define PASSWORD "Rübezahl"
#define PAYLOAD "01234567890"
        ck_assert(generate_send_key_and_salt(PASSWORD));

        char *const buffer = alloca(TOTAL_MSG_LEN);
        const int msg_len = snprintf(&buffer[MSG_IDX], MSG_LEN, PAYLOAD) + 1;

        pad(buffer, msg_len);

        for (int j = msg_len; j < MSG_LEN; j++)
                ck_assert_int_eq((unsigned char) buffer[j], MSG_LEN - msg_len);

        ck_assert(encrypt_message(buffer));

        ck_assert(!memcmp(&buffer[SALT_IDX], send_salt, crypto_pwhash_SALTBYTES));

        la_address_t *a = create_address("5.5.5.5");
        ck_assert(a);

        ck_assert(decrypt_message(buffer, PASSWORD, a));

        ck_assert(same_salt_as_before((unsigned char *) buffer, a));
        ck_assert(!memcmp(&buffer[SALT_IDX], a->salt, crypto_pwhash_SALTBYTES));
        ck_assert(!memcmp(send_salt, a->salt, crypto_pwhash_SALTBYTES));
        ck_assert(!memcmp(send_key, a->key, crypto_secretbox_KEYBYTES));

        ck_assert_str_eq(&buffer[MSG_IDX], PAYLOAD);
        
}
END_TEST

Suite *crypto_suite(void)
{
	Suite *s = suite_create("Addresses");

        /* Core test case */
        TCase *tc_core = tcase_create("Core");
        tcase_add_test(tc_core, check_encrypt_decrypt);
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
