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
        struct kw_tree_node_s *first;
        struct kw_tree_node_s *last;
        int count;
} kw_tree_t;

/* Defines */

#define is_root_node(node) (!node->parent)
#define is_left_child(node) (node->parent->left == node)
#define is_right_child(node) (node->parent->right == node)
#define is_leaf_node(node) (!node->left && !node->right)

void inject_binarytree_exit_function(void (*exit_function)(bool log_strerror,
                        const char *const fmt, ...));

void assert_tree_node_ffl(const kw_tree_node_t *node, const char *func,
                const char *file, int line);

void assert_tree_ffl(const kw_tree_t *tree, const char *func, const char *file,
                int line);

kw_tree_node_t *remove_tree_node(kw_tree_t *tree, kw_tree_node_t *node);

kw_tree_node_t *find_tree_node(kw_tree_t *tree, const void *payload,
                int (*compar)(const void *, const void *));

kw_tree_node_t *next_node_in_tree(kw_tree_node_t *node);

void add_to_tree(kw_tree_t *node_in_tree, kw_tree_node_t *new_node,
                int (*compar)(const void *, const void *));

void empty_tree(kw_tree_t *tree, void (*delete_payload)(const void *),
                bool free_nodes);

kw_tree_t *create_tree(void);

void free_tree(kw_tree_t *tree);

bool is_empty(kw_tree_t *tree);

int node_depth(const kw_tree_node_t *node);

int tree_depth(const kw_tree_t *tree);

#endif /* __binarytree_h */

/* vim: set autowrite expandtab: */
