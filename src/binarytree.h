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

#ifndef __binarytree_h
#define __binarytree_h

#include "stdbool.h"

#include "ndebug.h"

/* Assertions */

#define assert_tree_node(NODE) assert_tree_node_ffl(NODE, __func__, __FILE__, __LINE__)
#define assert_tree(TREE) assert_tree_ffl(TREE, __func__, __FILE__, __LINE__)

typedef struct kw_tree_node_s {
        struct kw_tree_node_s *left;
        struct kw_tree_node_s *right;
        struct kw_tree_node_s *parent;
        void *payload;
} kw_tree_node_t;

typedef enum kw_branch_side {
        kw_no_branch = 0,
        kw_left_branch = 1,
        kw_right_branch = 2
} kw_branch_side_t;

typedef struct kw_tree_s {
        struct kw_tree_node_s *root;
} kw_tree_t;

void assert_tree_node_ffl(const kw_tree_node_t *node, const char *func,
                const char *file, int line);

void assert_tree_ffl(const kw_tree_t *tree, const char *func, const char *file,
                int line);

kw_tree_node_t *remove_tree_node(kw_tree_t *const tree,
                kw_tree_node_t *const node);

kw_tree_node_t *find_tree_node(kw_tree_t *const tree,
                const void *const payload,
                int (*compar)(const void *, const void *));

kw_tree_node_t *first_tree_node(const kw_tree_t *const tree);

kw_tree_node_t *next_node_in_tree(kw_tree_node_t *const node);

void add_to_tree(kw_tree_t *node_in_tree, kw_tree_node_t *new_node,
                int (*compar)(const void *, const void *));

void empty_tree(kw_tree_t *const tree, void (*delete_payload)(const void *),
                bool free_nodes);

kw_tree_t *create_tree(void);

void free_tree(kw_tree_t *tree);

bool is_empty(kw_tree_t *tree);

#endif /* __binarytree_h */

/* vim: set autowrite expandtab: */
