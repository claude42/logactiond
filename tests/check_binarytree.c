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

#include <../src/binarytree.h>
#include <../src/binarytree.c>

/* Mocks */

void
log_message(int priority, const char *const fmt, va_list gp,
                const char *const add)
{
        assert(fmt);

	vfprintf(stderr, fmt, gp);
	if (add)
		fprintf(stderr, ": %s", add);
	fprintf(stderr, "\n");
}

void
la_log_verbose(const int priority, const char *const fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(priority, fmt, myargs, NULL);
        va_end(myargs);
}

void
die_hard(const char *const fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        log_message(LOG_ERR, fmt, myargs, NULL);
        va_end(myargs);

        exit(1);
}

static int
cmp(const void *s1, const void *s2)
{
        int result = strcmp((const char *) s1, (const char *) s2);
        la_log_verbose(LOG_INFO, "strcmp(%s, %s) = %i", (const char *) s1, (const char *) s2, result);
        return result;
}

/* Trees */

START_TEST (check_trees)
{
        kw_tree_t *tree = create_tree();
        ck_assert_int_eq(tree->count, 0);
        ck_assert(is_empty(tree));
        ck_assert(!tree->root);

        kw_tree_node_t fuenf = { .payload = "5" };
        add_to_tree(tree, &fuenf, cmp);

        // 5

        ck_assert_int_eq(tree->count, 1);
        kw_tree_node_t *n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, fuenf.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &fuenf);

        ck_assert_int_eq(node_depth(&fuenf), 1);
        ck_assert_int_eq(tree_depth(tree), 1);

        kw_tree_node_t zwei = { .payload = "2" };
        add_to_tree(tree, &zwei, cmp);

        //     2
        // 5

        ck_assert_int_eq(tree->count, 2);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, zwei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, fuenf.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &fuenf);

        ck_assert_int_eq(node_depth(&fuenf), 1);
        ck_assert_int_eq(node_depth(&zwei), 2);
        ck_assert_int_eq(tree_depth(tree), 2);

        kw_tree_node_t drei = { .payload = "3" };
        add_to_tree(tree, &drei, cmp);

        //     2
        //         3
        // 5

        ck_assert_int_eq(tree->count, 3);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, zwei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, drei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, fuenf.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &fuenf);

        ck_assert_int_eq(node_depth(&fuenf), 1);
        ck_assert_int_eq(node_depth(&zwei), 2);
        ck_assert_int_eq(node_depth(&drei), 3);
        ck_assert_int_eq(tree_depth(tree), 3);

        kw_tree_node_t neun = { .payload = "9" };
        add_to_tree(tree, &neun, cmp);

        //     2
        //         3
        // 5
        //     9   

        ck_assert_int_eq(tree->count, 4);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, zwei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, drei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, fuenf.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, neun.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &neun);

        ck_assert_int_eq(node_depth(&fuenf), 1);
        ck_assert_int_eq(node_depth(&zwei), 2);
        ck_assert_int_eq(node_depth(&drei), 3);
        ck_assert_int_eq(node_depth(&neun), 2);
        ck_assert_int_eq(tree_depth(tree), 3);

        ck_assert(find_tree_node(tree, "2", cmp) == &zwei);
        ck_assert(find_tree_node(tree, "3", cmp) == &drei);
        ck_assert(find_tree_node(tree, "5", cmp) == &fuenf);
        ck_assert(find_tree_node(tree, "9", cmp) == &neun);
        ck_assert(!find_tree_node(tree, "7", cmp));
        ck_assert(!find_tree_node(create_tree(), "nix", cmp));

        ck_assert(remove_tree_node(tree, &drei) == &drei);

        //     2
        // 5
        //     9   

        ck_assert_int_eq(tree->count, 3);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, zwei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, fuenf.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, neun.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &neun);

        add_to_tree(tree, &drei, cmp);
        ck_assert(remove_tree_node(tree, &zwei) == &zwei);

        //     3
        // 5
        //     9   

        ck_assert_int_eq(tree->count, 3);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, drei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, fuenf.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, neun.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &neun);

        add_to_tree(tree, &zwei, cmp);
        ck_assert(remove_tree_node(tree, &fuenf) == &fuenf);

        //     2
        // 3
        //     9

        ck_assert_int_eq(tree->count, 3);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, zwei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, drei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, neun.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &neun);

        ck_assert(remove_tree_node(tree, &zwei) == &zwei);

        // 3
        //     9

        ck_assert_int_eq(tree->count, 2);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, drei.payload);
        n = next_node_in_tree(n);
        ck_assert_str_eq(n->payload, neun.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &neun);

        ck_assert(remove_tree_node(tree, &drei) == &drei);

        // 9

        ck_assert_int_eq(tree->count, 1);
        n = first_tree_node(tree);
        ck_assert_str_eq(n->payload, neun.payload);
        n = next_node_in_tree(n);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, &neun);

        ck_assert(remove_tree_node(tree, &neun) == &neun);

        // 

        ck_assert_int_eq(tree->count, 0);
        n = first_tree_node(tree);
        ck_assert(!n);
        ck_assert_ptr_eq(tree->last, NULL);
        ck_assert(!find_tree_node(create_tree(), "nix", cmp));
}
END_TEST

START_TEST (check_empty_tree)
{
        kw_tree_t *t = create_tree();
        ck_assert(t);
        ck_assert(!t->root);

        add_to_tree(t, &(kw_tree_node_t) { .payload = "5" }, cmp);
        add_to_tree(t, &(kw_tree_node_t) { .payload = "8" }, cmp);
        add_to_tree(t, &(kw_tree_node_t) { .payload = "6" }, cmp);
        add_to_tree(t, &(kw_tree_node_t) { .payload = "1" }, cmp);
        add_to_tree(t, &(kw_tree_node_t) { .payload = "2" }, cmp);

        ck_assert_int_eq(t->count, 5);

        empty_tree(t, NULL, false);
        ck_assert_int_eq(t->count, 0);
        ck_assert(is_empty(t));
        ck_assert_ptr_eq(first_tree_node(t), NULL);
        ck_assert_ptr_eq(t->last, NULL);

        empty_tree(t, NULL, false);
        ck_assert(is_empty(t));

        empty_tree(NULL, NULL, false);
        ck_assert(is_empty(t));
}
END_TEST




Suite *commands_suite(void)
{
	Suite *s = suite_create("Binary Tree");

        /* Core test case */
        TCase *tc_main = tcase_create("Main");
        tcase_add_test(tc_main, check_trees);
        tcase_add_test(tc_main, check_empty_tree);
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
