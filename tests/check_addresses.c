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

#include <check.h>

#include <../src/addresses.c>
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

static bool shutdown_good = false;
static char shutdown_msg[] = "Shutdown message not set";

void
trigger_shutdown(int status, int saved_errno)
{
        la_log(LOG_INFO, "reached shutdown");
        if (!shutdown_good)
                ck_abort_msg(shutdown_msg);
}

/* Compare */

START_TEST (create_address_v4)
{
        const char a_str[] = "185.228.136.144";
        const in_port_t port = 80;
        la_address_t *a = create_address_port(a_str, port);
        if (!a)
                ck_abort_msg("Failed to create IP4 address");

        // TODO: compare to int
        ck_assert_int_eq(get_port(a), port);
        ck_assert_str_eq(a->text, a_str);
        ck_assert_str_eq(get_ip_version(a), "4");
        ck_assert_int_eq(a->prefix, 32);

        la_address_t *b = dup_address(a);
        if (!b)
                ck_abort_msg("Failed to duplicate IP4 address");

        // TODO: compare to int
        ck_assert_int_eq(get_port(b), port);
        ck_assert_str_eq(b->text, a_str);
        ck_assert_str_eq(get_ip_version(b), "4");
        ck_assert_int_eq(b->prefix, 32);
        ck_assert(!adrcmp(a, b));

        set_port(b, 80);
        ck_assert_int_eq(get_port(b), 80);

        const char d_str[] = "185.228.136.144/24";
        la_address_t *d = create_address_port(d_str, 80);
        if (!d)
                ck_abort_msg("Failed to create IP4 address");

        // TODO: compare to int
        ck_assert_int_eq(get_port(d), 80);
        ck_assert_str_eq(d->text, d_str);
        ck_assert_str_eq(get_ip_version(d), "4");
        ck_assert_int_eq(d->prefix, 24);

        free_address(d);
        free_address(b);
        free_address(a);

}
END_TEST

START_TEST (create_address_v6)
{
        const char a_str[] = "2602:fea7:c0:3::1";
        la_address_t *a = create_address(a_str);
        if (!a)
                ck_abort_msg("Failed to create IP6 address");

        // TODO: compare to int
        ck_assert_int_eq(get_port(a), 0);
        ck_assert_str_eq(a->text, a_str);
        ck_assert_str_eq(get_ip_version(a), "6");
        ck_assert_int_eq(a->prefix, 128);

        la_address_t *b = dup_address(a);
        if (!b)
                ck_abort_msg("Failed to duplicate IP6 address");

        // TODO: compare to int
        ck_assert_int_eq(get_port(b), 0);
        ck_assert_str_eq(b->text, a_str);
        ck_assert_str_eq(get_ip_version(b), "6");
        ck_assert_int_eq(b->prefix, 128);
        ck_assert(!adrcmp(a, b));

        set_port(b, 80);
        ck_assert_int_eq(get_port(b), 80);

        const char c_str[] = "2602:fea7:00c0:0003:0000:0000:0000:0000/64";
        const char c_result_str[] = "2602:fea7:c0:3::/64";
        la_address_t *c = create_address_port(c_str, 80);
        if (!c)
                ck_abort_msg("Failed to create IP6 address");
        //
        // TODO: compare to int
        ck_assert_int_eq(get_port(c), 80);
        ck_assert_str_eq(c->text, c_result_str);
        ck_assert_str_eq(get_ip_version(c), "6");
        ck_assert_int_eq(c->prefix, 64);

        ck_assert(adrcmp(a, c));
        ck_assert(cidr_match_sa((struct sockaddr *) &(a->sa), c));

        free_address(c);
        free_address(b);
        free_address(a);

}
END_TEST

START_TEST (create_invalid_address)
{
        ck_assert(!create_address("blafasel"));
        ck_assert(!create_address("1.2.3.4.5"));
        ck_assert(!create_address("1.2.3.4/100"));
        ck_assert(!create_address("1.2.3.4/foo"));
        ck_assert(!create_address("1.2.3.4/-5"));
        ck_assert(!create_address("1.2.3.4/"));
        // TODO more
}
END_TEST

/* Compare */

START_TEST (compare)
{
        kw_list_t *l = create_list();
        la_address_t *a1 = create_address("1.2.3.4");
        add_tail(l, (kw_node_t *) a1);
        add_tail(l, (kw_node_t *) create_address("2.3.4.0/24"));

        ck_assert(address_on_list_str("1.2.3.4", l));
        ck_assert(address_on_list_str("2.3.4.5", l));
        ck_assert(!address_on_list_str("3.4.5.6", l));

        ck_assert(!adrcmp(create_address("1.2.3.4"),
                                create_address_port("1.2.3.4", 80)));
        ck_assert(adrcmp(a1, create_address("2.3.4.5")));

        la_address_t *a2 = create_address("2602:fea7:c0:3::1");
        add_tail(l, (kw_node_t *) a2);
        ck_assert(adrcmp(a1, a2));
        ck_assert(address_on_list_str("2602:fea7:c0:3::1", l));
        la_address_t *a3 = create_address("2602:fea7:c0:3::/64");
        add_tail(l, (kw_node_t *) a3);
        ck_assert(address_on_list_str("2602:fea7:c0:3::5", l));

        free_address_list(l);

        l = create_list();
        la_address_t *a4 = create_address("1.2.3.4");
        a4->prefix = 24;
        add_tail(l, (kw_node_t *) a4);
        ck_assert(address_on_list(create_address("1.2.3.5"), l));
        a4 = create_address("2602:fea7:c0:3::1");
        a4->prefix = 64;
        add_tail(l, (kw_node_t *) a4);
        ck_assert(address_on_list(create_address("2602:fea7:c0:3::2"), l));

        free_address_list(l);
}
END_TEST

START_TEST (compare2)
{
        ck_assert_int_lt(adrcmp(create_address("1.2.3.4"), create_address("1.2.3.5")), 0);
        ck_assert_int_eq(adrcmp(create_address("1.2.3.5"), create_address("1.2.3.5")), 0);
        ck_assert_int_gt(adrcmp(create_address("1.2.3.6"), create_address("1.2.3.5")), 0);
        ck_assert_int_lt(adrcmp(create_address("2602:fea7:c0:3::1"), create_address("2602:fea7:c0:3::2")), 0);
        ck_assert_int_eq(adrcmp(create_address("2602:fea7:c0:3::2"), create_address("2602:fea7:c0:3::2")), 0);
        ck_assert_int_gt(adrcmp(create_address("2602:fea7:c0:3::3"), create_address("2602:fea7:c0:3::2")), 0);
        ck_assert_int_gt(adrcmp(create_address("1000::0001"), create_address("0100::0010")), 0);
        ck_assert_int_gt(adrcmp(create_address("1.2.3.4"), NULL), 0);
        ck_assert_int_lt(adrcmp(NULL, create_address("1.2.3.4")), 0);
        ck_assert_int_eq(adrcmp(NULL, NULL), 0);
}
END_TEST

START_TEST (match)
{
        la_address_t n;
        init_address(&n, "192.168.0.0/23");
        la_address_t a;
        init_address(&a, "192.168.0.1");
        ck_assert(cidr_match_sa((struct sockaddr *) &(a.sa), &n));
        init_address(&a, "192.168.1.1");
        ck_assert(cidr_match_sa((struct sockaddr *) &(a.sa), &n));
        init_address(&a, "192.168.2.1");
        ck_assert(!cidr_match_sa((struct sockaddr *) &(a.sa), &n));
        init_address(&n, "192.168.0.1/32");
        init_address(&a, "192.168.0.1");
        ck_assert(cidr_match_sa((struct sockaddr *) &(a.sa), &n));
        init_address(&a, "192.168.0.2");
        ck_assert(!cidr_match_sa((struct sockaddr *) &(a.sa), &n));

        init_address(&n, "2a03:4000:23:8c::/64");
        init_address(&a, "2a03:4000:23:8c::1");
        ck_assert(cidr_match_sa((struct sockaddr *) &(a.sa), &n));
        init_address(&a, "2a03:4000:23:8d::1");
        ck_assert(!cidr_match_sa((struct sockaddr *) &(a.sa), &n));
}
END_TEST

Suite *addresses_suite(void)
{
	Suite *s = suite_create("Addresses");

        /* Core test case */
        TCase *tc_create = tcase_create("Create");
        tcase_add_test(tc_create, create_address_v4);
        tcase_add_test(tc_create, create_address_v6);
        tcase_add_test(tc_create, create_invalid_address);
        suite_add_tcase(s, tc_create);

        TCase *tc_compare = tcase_create("Compare");
        tcase_add_test(tc_compare, compare);
        tcase_add_test(tc_compare, compare2);
        tcase_add_test(tc_compare, match);
        suite_add_tcase(s, tc_compare);

        return s;
}

int
main(int argc, char *argv[])
{
        int number_failed = 0;
        Suite *s = addresses_suite();
        SRunner *sr = srunner_create(s);

        srunner_run_all(sr, CK_NORMAL);
        number_failed = srunner_ntests_failed(sr);
        srunner_free(sr);
        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
 
/* vim: set autowrite expandtab: */
