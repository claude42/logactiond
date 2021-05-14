/*
 *  logactiond - trigger actions based on logfile contents
 *  Copyright (C) 2019-2021 Klaus Wissmann

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

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#include "ndebug.h"
#include "nodelist.h"

static void
default_nodelist_exit_function(bool log_strerror, const char *const fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        vfprintf(stderr, fmt, myargs);
        va_end(myargs);
        exit(EXIT_FAILURE);
}

static void (*nodelist_exit_function)(bool log_strerror, const char *const fmt, ...) =
        default_nodelist_exit_function;

void
inject_nodelist_exit_function(void (*exit_function)(bool log_strerror,
                        const char *const fmt, ...))
{
        nodelist_exit_function = exit_function;
}

void
assert_node_ffl(const kw_node_t *node, const char *func, const char *file,
                int line)
{
        if (!node)
                nodelist_exit_function(false, "%s:%u: %s: Assertion 'node' "
                                "failed.", file, line, func);
        if (!(node->succ || node->pred))
                nodelist_exit_function(false, "%s:%u: %s: Assertion 'node->succ "
                                "|| node->pred' failed.", file, line, func);
        if (!(node->succ != node->pred))
                nodelist_exit_function(false, "%s:%u: %s: Assertion 'node->succ "
                                "!= node->pred' failed.", file, line, func);
        if (node->pred && node->pred->succ != node)
                nodelist_exit_function(false, "%s:%u: %s: Assertion "
                                "'node->pred->succ == node' failed.", file,
                                line, func);

        if (node->succ && node->succ->pred != node)
                nodelist_exit_function(false, "%s:%u: %s: Assertion "
                                "'node->succ->pred == node' failed.", file,
                                line, func);
}

void
assert_list_ffl(const kw_list_t *list, const char *func, const char *file,
                int line)
{
        if (!list)
                nodelist_exit_function(false, "%s:%u: %s: Assertion 'list' "
                                "failed.", file, line, func);
        if (!(list->head && list->tail_pred))
                nodelist_exit_function(false, "%s:%u: %s: Assertion "
                                "'list->head && list->tail_pred' failed.",
                                file, line, func);
        if (list->tail)
                nodelist_exit_function(false, "%s:%u: %s: Assertion "
                                "'!list->tail' failed.",
                                file, line, func);

        for (kw_node_t *node = list->head; node->succ; node = node->succ)
                assert_node_ffl(node, func, file, line);
}

/*
 * Will strdup(nodename)!
 */

static void
init_node(kw_node_t *node, const int pri, const char *const nodename)
{
        node->succ = node->pred = NULL;
        node->pri = pri;

        if (nodename)
        {
                node->nodename = strdup(nodename);
                if (!node->nodename)
                        nodelist_exit_function(false, "Memory exhausted");
        }
        else
        {
                node->nodename = NULL;
        }
}

void *
create_node(size_t size, const int pri, const char *const nodename)
{
        kw_node_t *const result = malloc(size);
        if (!result)
                nodelist_exit_function(false, "Memory exhausted");

        init_node(result, pri, nodename);

        return result;
}

void *
create_node0(size_t size, const int pri, const char *const nodename)
{
        kw_node_t *const result = calloc(size, 1);
        if (!result)
                nodelist_exit_function(false, "Memory exhausted");

        init_node(result, pri, nodename);

        return result;
}

void
free_node(kw_node_t *const node)
{
        free(node->nodename);
        free(node);
}

void
init_list(kw_list_t *const list)
{
        list->head = (kw_node_t *) &list->tail;
        list->tail = NULL;
        list->tail_pred = (kw_node_t *) &list->head;
}

/*
 * Can be freed with free()
 */

kw_list_t *
create_list(void)
{
        kw_list_t *const result = malloc(sizeof *result);
        if (!result)
                nodelist_exit_function(false, "Memory exhausted");

        init_list(result);

        return result;
}

/*
 * When ex_node == list->head, new_node is inserted at the beginning of the list.
 * Wenn ex_node == list->tail, new_node is inserted at the end of the list
 */

void
insert_node_after(kw_node_t *ex_node, kw_node_t *const new_node)
{
        if (!ex_node || !new_node)
                return;
        assert_node(ex_node);

        /* if ex_node is the list header, insert at end of list */
        if (!ex_node->succ)
                ex_node = ex_node->pred;

        new_node->pred = ex_node;
        new_node->succ = ex_node->succ;
        ex_node->succ->pred = new_node;
        ex_node->succ = new_node;
}


void
insert_node_before(kw_node_t *ex_node, kw_node_t *const new_node)
{
        if (!ex_node || !new_node)
                return;
        assert_node(ex_node);

        /* if ex_node is the list header, insert at beginning of list */
        if (!ex_node->pred)
                ex_node = ex_node->succ;

        new_node->pred = ex_node->pred;
        new_node->succ = ex_node;
        ex_node->pred->succ = new_node;
        ex_node->pred = new_node;
}

/* Will return the next node (.e. the node after the removed node) in the list.
 * Will return NULL in case the removed node was the last in the list */

kw_node_t *
remove_node(kw_node_t *const node)
{
        if (!node || !node->pred || !node->succ)
                return NULL;

        assert_node(node); assert(is_list_node(node));

        kw_node_t *const result = node->succ->succ ? node->succ : NULL;

        node->pred->succ = node->succ;
        node->succ->pred = node->pred;

        return result;
}

void
reprioritize_node(kw_node_t *const node, int delta_pri)
{
        if (!delta_pri)
                return;

        assert_node(node); assert(is_list_node(node));
        node->pri += delta_pri;


        /* When delta_pri > 0 reorder only if new priority is bigger than
         * previous node (and previos node is not the head node). Respectively
         * the other way round... */
        if (delta_pri > 0 && node->pri < LONG_MAX &&
                        node->pred->pred && node->pri > node->pred->pri)
        {
                (void) remove_node(node);
                kw_node_t *tmp = node->pred;

                while (tmp->pred && node->pri > tmp->pri)
                        tmp = tmp->pred;

                insert_node_after(tmp, node);
        }
        else if (delta_pri < 0 && node->pri > LONG_MIN &&
                        node->succ->succ && node->pri < node->succ->pri)
        {
                (void) remove_node(node);
                kw_node_t *tmp = node->succ;

                while (tmp->succ && node->pri < tmp->pri)
                        tmp = tmp->succ;

                insert_node_before(tmp, node);
        }
}

void
move_to_head(kw_node_t *const node)
{
        if (!node)
                return;

        assert_node(node); assert(is_list_node(node));

        if (!node->pred->pred)
                return;

        kw_node_t *tmp = node->pred;
        (void) remove_node(node);
        for (; tmp->pred->pred; (tmp = tmp->pred))
                ;

        insert_node_before(tmp, node);
        if (node->pri < tmp->pri)
                node->pri = tmp->pri + 1;
}

void
add_head(kw_list_t *const list, kw_node_t *const node)
{
        if (!list || !node)
                return;

        assert_list(list);

        node->succ = list->head;
        node->pred = (kw_node_t *) &list->head;
        list->head = node;
        node->succ->pred = node;
}

void
add_tail(kw_list_t *const list, kw_node_t *const node)
{
        if (!list || !node)
                return;

        assert_list(list);

        node->succ = (kw_node_t *) &list->tail;
        node->pred = list->tail_pred;
        list->tail_pred = node;
        node->pred->succ = node;
}

kw_node_t *
get_head(const kw_list_t *const list)
{
        if (!list)
                return NULL;
        assert_list(list);

        if (is_list_empty(list))
                return NULL;
        else
                return list->head;
}

kw_node_t *
get_tail(const kw_list_t *const list)
{
        if (!list)
                return NULL;
        assert_list(list);

        if (is_list_empty(list))
                return NULL;
        else
                return list->tail_pred;
}

kw_node_t *
rem_head(kw_list_t *const list)
{
        if (!list)
                return NULL;
        assert_list(list);

        if (is_list_empty(list))
                return NULL;

        kw_node_t *const result = list->head;
        list->head = result->succ;
        result->succ->pred = (kw_node_t *) &list->head;

        return result;
}

kw_node_t *
rem_tail(kw_list_t *const list)
{
        if (!list)
                return NULL;
        assert_list(list);

        if (is_list_empty(list))
                return NULL;

        kw_node_t *const result = list->tail_pred;
        list->tail_pred = result->pred;
        result->pred->succ = (kw_node_t *) &list->tail;

        return result;
}

kw_node_t *
get_list_iterator(const kw_list_t *const list)
{
        if (!list)
                return NULL;
        assert_list(list);

        return (kw_node_t *) &list->head;
}

kw_node_t *
get_next_node(kw_node_t **const iterator)
{
        assert_node(*iterator);

        if (!(*iterator)->succ)
                return NULL;

        *iterator = (*iterator)->succ;

        if ((*iterator)->succ == NULL)
                return NULL;
        else
                return *iterator;
}

void
empty_list(kw_list_t *const list, void (*free_node_func)(void *const))
{
        if (!list)
                return;

        kw_node_t *node = list->head;

        while (node->succ)
        {
                kw_node_t *const tmp = node;
                node = node->succ;
                free(tmp->nodename);
                tmp->nodename = NULL;
                if (free_node_func)
                        free_node_func(tmp);
                else
                        free(tmp);
        }

        init_list(list);
}

void
free_list(kw_list_t *const list, void (*free_node_func)(void *const))
{
        empty_list(list, free_node_func);

        free(list);
}

int
list_length(const kw_list_t *const list)
{
        if (!list)
                return 0;
        assert_list(list);

        int result = 0;

        for (kw_node_t *node = list->head; node->succ;
                        (node = node->succ))
                result++;

        return result;
}


/* vim: set autowrite expandtab: */
