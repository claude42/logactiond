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

#ifndef __nodelist_h
#define __nodelist_h

#include <stdbool.h>
#include <stddef.h>

#include "ndebug.h"

/* Assertions */

#define assert_list(LIST) assert_list_ffl(LIST, __func__, __FILE__, __LINE__)
#define assert_node(NODE) assert_node_ffl(NODE, __func__, __FILE__, __LINE__)

/*
 * functions missing
 *
 * enqueue
 * findname
 */

typedef struct kw_node_s {
        struct kw_node_s *succ;
        struct kw_node_s *pred;
        long pri;
        char *nodename;
} kw_node_t;

typedef struct kw_list_s {
        kw_node_t *head;
        kw_node_t *tail;
        kw_node_t *tail_pred;
} kw_list_t;

typedef void * kw_iterator;

#define is_list_empty(x) \
        ( ((x)->tail_pred) == (kw_node_t *)(x) )

#define is_list_node(x) \
        (((kw_node_t *) x)->succ && ((kw_node_t *) x)->pred)

#define FOREACH(TYPE, VAR, LIST) \
        for (TYPE *VAR = (TYPE *) (LIST)->head; \
                        ((kw_node_t *) VAR)->succ; \
                        VAR = (TYPE *) ((kw_node_t *) VAR)->succ)

#define FOREACH_REUSE_VAR(TYPE, VAR, LIST) \
        for (VAR = (TYPE *) (LIST)->head; \
                        ((kw_node_t *) VAR)->succ; \
                        VAR = (TYPE *) ((kw_node_t *) VAR)->succ)

#define GET_FIRST(TYPE, VAR, LIST) \
        TYPE *VAR = (TYPE *) (LIST)->head

#define IS_NODE(VAR) \
        ((kw_node_t *) VAR)->succ

#define GET_NEXT(TYPE, VAR) \
        VAR = (TYPE *) ((kw_node_t *) VAR)->succ


void inject_nodelist_exit_function(void (*exit_function)(bool log_strerror,
                        const char *const fmt, ...));

void *create_node(size_t size, const int pri, const char *const nodename);

void *create_node0(size_t size, const int pri, const char *const nodename);

void free_node(kw_node_t *node);

void init_list(kw_list_t *list);

kw_list_t *create_list(void);

void empty_list(kw_list_t *list, void (*free_node)(void *));

void free_list(kw_list_t *list, void (*free_node)(void *));

void add_head(kw_list_t *list, kw_node_t *node);

void add_tail(kw_list_t *list, kw_node_t *node);

kw_node_t *rem_head(kw_list_t *list);

kw_node_t *get_list_iterator(const kw_list_t *list);

kw_node_t *get_next_node(kw_node_t **iterator);

int list_length(const kw_list_t *list);

kw_node_t *get_head(const kw_list_t *list);

kw_node_t *get_tail(const kw_list_t *list);

void insert_node_before(kw_node_t *ex_node, kw_node_t *new_node);

kw_node_t *remove_node(kw_node_t *node);

void reprioritize_node(kw_node_t *const node, int delta_pri);

void move_to_head(kw_node_t *const node);

void assert_node_ffl(const kw_node_t *node, const char *func, const char *file,
                int line);

void assert_list_ffl(const kw_list_t *list, const char *func, const char *file,
                int line);


#endif /* __nodelist_h */

/* vim: set autowrite expandtab: */
