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
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>


#include <check.h>

#include <../src/nodelist.h>
#include <../src/nodelist.c>
#include <../src/logactiond.h>

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

/*static int
cmp(const void *s1, const void *s2)
{
        int result = strcmp((const char *) s1, (const char *) s2);
        la_log_verbose(LOG_INFO, "strcmp(%s, %s) = %i", (const char *) s1, (const char *) s2, result);
        return result;
}*/

/* Nodelist */

void x_assert_node(const kw_node_t *node)
{
        ck_assert(node);
        ck_assert(node->succ || node->pred);
        ck_assert(node->succ != node->pred);
        ck_assert(!node->pred || node->pred->succ == node);
        ck_assert(!node->succ || node->succ->pred == node);
}

void x_assert_list(const kw_list_t *list)
{
        ck_assert(list);
        ck_assert(list->head.succ);
        ck_assert(!list->head.pred);
        ck_assert(list->tail.pred);
        ck_assert(!list->tail.succ);
        for (kw_node_t *node = list->head.succ; node->succ; node = node->succ)
        {
                x_assert_node(node);
        }
}

void print_list(const kw_list_t *list)
{
        fprintf(stderr, "List: ");
        for (kw_node_t *n = list->head.succ; n->succ; n = n->succ)
        {
                fprintf(stderr, "%s(%i) ->", n->name, n->pri);
        }
        fprintf(stderr, "\n");
}


START_TEST (check_nodelist)
{
        kw_list_t *l = create_list();
        print_list(l);
        x_assert_list(l);
        ck_assert_int_eq(list_length(l), 0);

        // List: empty

        kw_node_t fuenf = {
                .pri = 5,
                .name ="fünf",
        };
        add_head(l, &fuenf);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &fuenf);
        ck_assert_int_eq(list_length(l), 1);

        // List: fünf

        kw_node_t eins = {
                .pri = 1,
                .name = "eins",
        };
        add_tail(l, &eins);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        x_assert_node(&eins);
        ck_assert_ptr_eq(fuenf.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &fuenf);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 2);

        // List: fünf -> eins

        kw_node_t vier = {
                .pri = 4,
                .name = "vier",
        };
        insert_node_after(&fuenf, &vier);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        x_assert_node(&vier);
        x_assert_node(&eins);
        ck_assert_ptr_eq(fuenf.succ, &vier);
        ck_assert_ptr_eq(vier.pred, &fuenf);
        ck_assert_ptr_eq(vier.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &vier);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 3);

        // List: fünf -> vier -> eins

        kw_node_t drei = {
                .pri = 3,
                .name = "drei",
        };
        insert_node_before(&eins, &drei);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        x_assert_node(&vier);
        x_assert_node(&drei);
        x_assert_node(&eins);
        ck_assert_ptr_eq(fuenf.succ, &vier);
        ck_assert_ptr_eq(vier.pred, &fuenf);
        ck_assert_ptr_eq(vier.succ, &drei);
        ck_assert_ptr_eq(drei.pred, &vier);
        ck_assert_ptr_eq(drei.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &drei);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 4);

        // List: fünf -> vier -> drei -> eins

        kw_node_t *it = get_list_iterator(l);
        ck_assert(it);
        kw_node_t *n = get_next_node(&it);
        ck_assert_ptr_eq(n, &fuenf);
        n = get_next_node(&it);
        ck_assert_ptr_eq(n, &vier);
        n = get_next_node(&it);
        ck_assert_ptr_eq(n, &drei);
        n = get_next_node(&it);
        ck_assert_ptr_eq(n, &eins);
        n = get_next_node(&it);
        ck_assert_ptr_eq(n, NULL);
        n = get_next_node(&it);
        ck_assert_ptr_eq(n, NULL);

        // ---

        kw_node_t null = {
                .pri = 0,
                .name = "null",
        };
        add_tail(l, &null);
        move_to_head(&null);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&null);
        x_assert_node(&fuenf);
        x_assert_node(&vier);
        x_assert_node(&drei);
        x_assert_node(&eins);
        ck_assert_ptr_eq(null.succ, &fuenf);
        ck_assert_ptr_eq(fuenf.pred, &null);
        ck_assert_ptr_eq(fuenf.succ, &vier);
        ck_assert_ptr_eq(vier.pred, &fuenf);
        ck_assert_ptr_eq(vier.succ, &drei);
        ck_assert_ptr_eq(drei.pred, &vier);
        ck_assert_ptr_eq(drei.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &drei);
        ck_assert_ptr_eq(get_head(l), &null);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 5);

        // List: null -> fünf -> vier -> drei -> eins

        rem_head(l);
        reprioritize_node(&vier, -2);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        x_assert_node(&drei);
        x_assert_node(&vier);
        ck_assert_int_eq(vier.pri, 2);
        x_assert_node(&eins);
        ck_assert_ptr_eq(fuenf.succ, &drei);
        ck_assert_ptr_eq(drei.pred, &fuenf);
        ck_assert_ptr_eq(drei.succ, &vier);
        ck_assert_ptr_eq(vier.pred, &drei);
        ck_assert_ptr_eq(vier.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &vier);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 4);

        // List: fünf -> drei -> vier -> eins

        reprioritize_node(&vier, 4);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&vier);
        ck_assert_int_eq(vier.pri, 6);
        x_assert_node(&fuenf);
        x_assert_node(&drei);
        x_assert_node(&eins);
        ck_assert_ptr_eq(vier.succ, &fuenf);
        ck_assert_ptr_eq(fuenf.pred, &vier);
        ck_assert_ptr_eq(fuenf.succ, &drei);
        ck_assert_ptr_eq(drei.pred, &fuenf);
        ck_assert_ptr_eq(drei.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &drei);
        ck_assert_ptr_eq(get_head(l), &vier);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 4);

        // List: vier -> fünf -> drei -> eins

        remove_node(&drei);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&vier);
        x_assert_node(&fuenf);
        x_assert_node(&eins);
        ck_assert_ptr_eq(vier.succ, &fuenf);
        ck_assert_ptr_eq(fuenf.pred, &vier);
        ck_assert_ptr_eq(fuenf.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &fuenf);
        ck_assert_ptr_eq(get_head(l), &vier);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 3);

        // ---

        rem_head(l);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        x_assert_node(&eins);
        ck_assert_ptr_eq(fuenf.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &fuenf);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 2);

        // ---

        rem_tail(l);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &fuenf);
        ck_assert_int_eq(list_length(l), 1);


}
END_TEST

START_TEST (check_edgecases)
{

        kw_list_t *l = create_list();
        ck_assert(!get_head(NULL));
        ck_assert(!get_head(l));
        ck_assert(!get_tail(NULL));
        ck_assert(!get_tail(l));
        ck_assert(!rem_head(NULL));
        ck_assert(!rem_head(l));
        ck_assert(!rem_tail(NULL));
        ck_assert(!rem_tail(l));

        ck_assert(!get_list_iterator(NULL));
        kw_node_t *it = get_list_iterator(l);
        ck_assert(it);
        ck_assert(!get_next_node(&it));
        ck_assert(!get_next_node(&it));

        ck_assert_int_eq(list_length(NULL), 0);
        ck_assert_int_eq(list_length(l), 0);

        // ---



        kw_node_t eins = {
                .pri = 1,
                .name ="eins",
        };
        kw_node_t fuenf = {
                .pri = 5,
                .name ="fünf",
        };

        add_head(l, &fuenf);
        // must not fail
        add_head(NULL, &eins);
        add_tail(NULL, &eins);
        add_head(l, NULL);
        x_assert_list(l);
        add_tail(l, NULL);
        x_assert_list(l);
        ck_assert_int_eq(list_length(l), 1);

        insert_node_before(NULL, NULL);
        insert_node_before(NULL, &eins);
        insert_node_before(&fuenf, NULL);

        // ---
        insert_node_before(&(l->head), &eins);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&eins);
        x_assert_node(&fuenf);
        ck_assert_ptr_eq(eins.succ, &fuenf);
        ck_assert_ptr_eq(fuenf.pred, &eins);
        ck_assert_ptr_eq(get_head(l), &eins);
        ck_assert_ptr_eq(get_tail(l), &fuenf);
        ck_assert_int_eq(list_length(l), 2);

        // ---
        rem_head(l);
        insert_node_after(&(l->tail), &eins);
        print_list(l);
        x_assert_list(l);
        x_assert_node(&fuenf);
        x_assert_node(&eins);
        ck_assert_ptr_eq(fuenf.succ, &eins);
        ck_assert_ptr_eq(eins.pred, &fuenf);
        ck_assert_ptr_eq(get_head(l), &fuenf);
        ck_assert_ptr_eq(get_tail(l), &eins);
        ck_assert_int_eq(list_length(l), 2);

        // must not crash, not alter list
        rem_head(l);
        remove_node(&(l->head));
        x_assert_list(l);
        remove_node(&(l->tail));
        x_assert_list(l);
        remove_node(NULL);
        x_assert_list(l);


}
END_TEST



Suite *commands_suite(void)
{
	Suite *s = suite_create("Binary Tree");

        /* Core test case */
        TCase *tc_main = tcase_create("Main");
        tcase_add_test(tc_main, check_nodelist);
        tcase_add_test(tc_main, check_edgecases);
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
