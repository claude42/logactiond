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
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>

#include "ndebug.h"
#include "binarytree.h"

static void
default_binarytree_exit_function(bool log_strerror, const char *const fmt, ...)
{
        va_list myargs;

        va_start(myargs, fmt);
        vfprintf(stderr, fmt, myargs);
        va_end(myargs);
        exit(EXIT_FAILURE);
}

static void (*binarytree_exit_function)(bool log_strerror, const char *const fmt, ...) =
        default_binarytree_exit_function;

void
inject_binarytree_exit_function(void (*exit_function)(bool log_strerror,
                        const char *const fmt, ...))
{
        binarytree_exit_function = exit_function;
}

void
assert_tree_node_ffl(const kw_tree_node_t *node, const char *func,
                const char *file, int line)
{
        if (!node)
                binarytree_exit_function(false, "%s:%u: %s: Assertion 'node' "
                                "failed.", file, line, func);
        if (node->parent && node->parent->left != node && node->parent->right != node)
                binarytree_exit_function(false, "%s:%u: %s: Assertion 'node "
                                "is son of parent' failed.", file, line, func);
        if (node->left && node->left->parent != node)
                binarytree_exit_function(false, "%s:%u: %s: Assertion 'parent "
                                "of left is me' failed.", file, line, func);
        if (node->right && node->right->parent != node)
                binarytree_exit_function(false, "%s:%u: %s: Assertion 'parent "
                                "of right is me' failed.", file, line, func);
}

void
assert_tree_ffl(const kw_tree_t *tree, const char *func, const char *file,
                int line)
{
        if (!tree)
                binarytree_exit_function(false, "%s:%u: %s: Assertion 'tree' "
                                "failed.", file, line, func);
        if (tree->root)
        {
                assert_tree_node_ffl(tree->root, func, file, line);
                assert(!tree->root->parent);
                assert_tree_node_ffl(tree->first, func, file, line);
                assert_tree_node_ffl(tree->last, func, file, line);
        }
}

/*
 * Reattach node2 to end of node1's sub branch of the specified side. I.e.
 * reattach(foo, bar, kw_left_branch) would attach bar to the end of foo's
 * left sub branch.
 * */

static void
reattach_to_end_of_tree(kw_tree_node_t *const node1,
                kw_tree_node_t *const node2, kw_branch_side_t side)
{
        if (!node2)
                /* nothing to do */
                return;
        assert_tree_node(node1);
        // don't assert_tree_node(node2) because it might not be properly
        // initialized yet
        assert(side == kw_left_branch || side == kw_right_branch);

        kw_tree_node_t *q = node1;

        if (side == kw_left_branch)
        {
                while (q->left)
                        q = q->left;
                q->left = node2;
        }
        else
        {
                while (q->right)
                        q = q->right;
                q->right = node2;
        }

        node2->parent = q;
}

/*
 * - take left subtree of node and assign to parent
 * - tack on right subtree of node to right end of former left subtree
 *   of node
 */

static void
try_left_branch(kw_tree_node_t **ptr, kw_tree_node_t *node)
{
        assert(ptr); assert(node);

        *ptr = node->left;
        node->left->parent = node->parent;
        reattach_to_end_of_tree(node->left,
                        node->right, kw_right_branch);
}

/*
 * - take right subtree of node and assign to parent
 * - tack on left subtree of node to left end of former right subtree
 *   of node
 */

static void
try_right_branch(kw_tree_node_t **ptr, kw_tree_node_t *node)
{
        assert(ptr); assert(node);

        *ptr = node->right;
        node->right->parent = node->parent;
        reattach_to_end_of_tree(node->right,
                        node->left, kw_left_branch);
}

static kw_tree_node_t *
leftmost_tree_node(kw_tree_node_t *const node)
{
        assert_tree_node(node);
        kw_tree_node_t *result = node;

        while (result->left)
                result = result->left;

        return result;
}

static kw_tree_node_t *
rightmost_tree_node(kw_tree_node_t *const node)
{
        assert_tree_node(node);
        kw_tree_node_t *result = node;

        while (result->right)
                result = result->right;

        return result;
}

kw_tree_node_t *
remove_tree_node(kw_tree_t *const tree, kw_tree_node_t *const node)
{
        assert_tree(tree); assert_tree_node(node);

        kw_tree_node_t **ptr = NULL;

        /*
         * - if removed node has no subtree, simply assign NULL to parent
         * - else if left sub tree exists
         *   - take left subtree assign to parent
         *     - if right tree exist, tack on right subtree to right end of
         *       former left subtree
         * - else if right subtree exists vice verca
         * - clean pointers of removed node
         */

        /* ptr is where the remaining subtree will be attached to */
        if (is_root_node(node))
                /* either set as the root of the tree */
                ptr = &tree->root;
        else if (is_left_child(node))
                /* or to the left of the remove notes parent */
                ptr = &node->parent->left;
        else if (is_right_child(node))
                /* or to the right */
                ptr = &node->parent->right;
        else
                /* or something's really wrong with this tree */
                assert(false);

        /* Used to alternatingly use left or right subtree */
        static int left_or_right = 0;

        if (is_leaf_node(node))
        {
                *ptr = NULL;
        }
        else
        {
                if ((left_or_right++ % 2) == 0)
                {
                        if (node->left)
                                try_left_branch(ptr, node);
                        else if (node->right)
                                try_right_branch(ptr, node);
                }
                else
                {
                        if (node->right)
                                try_right_branch(ptr, node);
                        else if (node->left)
                                try_left_branch(ptr, node);
                }
        }

        /* reassign first / last if necessary */
        if (node == tree->first && node == tree->last)
        {
                tree->first = tree->last = NULL;
        }
        else if (node == tree->first)
        {
                if (node->right)
                        tree->first = leftmost_tree_node(node->right);
                else
                        tree->first = node->parent;
        }
        else if (node == tree->last)
        {
                if (node->left)
                        tree->last = rightmost_tree_node(node->left);
                else
                        tree->last = node->parent;
        }

        /* clean up removed node */
        node->left = node->right = node->parent = NULL;

        tree->count--;

        return node;

}

kw_tree_node_t *
find_tree_node(kw_tree_t *const tree, const void *const payload,
                int (*compar)(const void *, const void *))
{
        assert_tree(tree); assert(compar);

        if (!payload || !tree->root)
                return NULL;
        assert_tree_node(tree->root);

        kw_tree_node_t *result = tree->root;
        for (;;)
        {
                const int cmp = compar(result->payload, payload);
                if (cmp == 0)
                        return result;
                else if (cmp < 0 && result->right)
                        result = result->right;
                else if (cmp > 0 && result->left)
                        result = result->left;
                else
                        return NULL;
        }

        /* control flow must not reach this point */
        assert(false);
        return result;
}

static void
attach_to_node(kw_tree_node_t *const parent, kw_tree_node_t *const node,
                kw_tree_node_t *const left,
                kw_tree_node_t *const right, const kw_branch_side_t side)
{
        assert(node);
        assert(!parent || (side == kw_left_branch || side == kw_right_branch));

        /* create link from parent in case parent is non-NULL and a proper
         * branch side has been specified */
        if (parent)
        {
                if (side == kw_left_branch)
                        parent->left = node;
                else
                        parent->right = node;
        }

        node->left = left;
        node->right = right;
        node->parent = parent;
}

kw_tree_node_t *
next_node_in_tree(kw_tree_node_t *const node)
{
        assert_tree_node(node);

        if (node->right)
        {
                /* if the current node has a right son, visit it */
                return leftmost_tree_node(node->right);
        }
        else
        {
                /* otherwise go up until we find a node which the current son
                 * is not a right son of */
                kw_tree_node_t *result = node;
                while (result->parent && result == result->parent->right)
                        result = result->parent;

                return result->parent;
        }
}

/*
 * Will add the new element at the correct position in the tree according to
 * the compar function.
 *
 * Will return kw_left_branch if the new element was put at the beginning of
 * the tree, kw_right_branch if put at the end and kw_no_branch otherwise.
 */

static kw_branch_side_t
recursively_add_to_tree(kw_tree_node_t *const node_in_tree,
                kw_tree_node_t *const new_node,
                int (*compar)(const void *, const void *))
{
        assert_tree_node(node_in_tree); assert(new_node); assert(compar);

        if (compar(new_node->payload, node_in_tree->payload) <= 0)
        {
                if (node_in_tree->left)
                {
                        if (recursively_add_to_tree(node_in_tree->left,
                                                new_node, compar) == kw_left_branch)
                                return kw_left_branch;
                        else
                                return kw_no_branch;
                }
                else
                {
                        attach_to_node(node_in_tree, new_node, NULL, NULL, kw_left_branch);
                        return kw_left_branch;
                }
        }
        else
        {
                if (node_in_tree->right)
                {
                        if (recursively_add_to_tree(node_in_tree->right,
                                                new_node, compar) == kw_right_branch)
                                return kw_right_branch;
                        else
                                return kw_no_branch;
                }
                else
                {
                        attach_to_node(node_in_tree, new_node, NULL, NULL, kw_right_branch);
                        return kw_right_branch;
                }
        }
}

void
add_to_tree(kw_tree_t *const tree, kw_tree_node_t *const node,
                int (*compar)(const void *, const void *))
{
        assert_tree(tree); assert(node); assert(compar);

        if (tree->root)
        {
                switch (recursively_add_to_tree(tree->root, node, compar))
                {
                case kw_left_branch:
                        tree->first = node;
                        break;
                case kw_right_branch:
                        tree->last = node;
                        break;
                case kw_no_branch:
                        break;
                }
        }
        else
        {
                tree->root = tree->first = tree->last = node;
                attach_to_node(NULL, node, NULL, NULL, kw_no_branch);
        }

        tree->count++;
}

static void
recursively_empty_tree(kw_tree_node_t *const node,
                void (*delete_payload)(const void *), bool free_nodes)
{
        assert_tree_node(node);

        if (node->left)
                recursively_empty_tree(node->left, delete_payload, free_nodes);
        if (node->right)
                recursively_empty_tree(node->right, delete_payload, free_nodes);

        if (delete_payload)
                delete_payload(node->payload);
        if (free_nodes)
                free(node);
}

/* 
 * Deallocates all nodes of the tree. Will not take care to keep tree structure
 * intact during deletion. Will not free kw_tree_t structure itself, just set
 * root to NULL.
 */

void
empty_tree(kw_tree_t *const tree, void (*delete_payload)(const void *),
                bool free_nodes)
{
        if (tree && tree->root)
        {
                assert_tree(tree);
                recursively_empty_tree(tree->root, delete_payload, free_nodes);
                tree->root = tree->first = tree->last = NULL;
                tree->count = 0;
        }
}

static void
recursively_walk_tree(kw_tree_node_t *const node,
                void (*process_payload(const void *)))
{
        assert_tree_node(node); assert(process_payload);

        if (node->left)
                recursively_walk_tree(node->left, process_payload);

        process_payload(node->payload);

        if (node->left)
                recursively_walk_tree(node->left, process_payload);
}

void
walk_tree(kw_tree_t *const tree, void (*process_payload(const void *)))
{
        if (tree && tree->root)
        {
                assert_tree(tree); assert(process_payload);
                recursively_walk_tree(tree->root, process_payload);
        }
}

kw_tree_t *
create_tree(void)
{
        kw_tree_t *const result = calloc(sizeof *result, 1);

        return result;
}

void
free_tree(kw_tree_t *tree)
{
        free(tree);
}

bool
is_empty(kw_tree_t *tree)
{
        return !(tree && tree->root);
}

int
node_depth(const kw_tree_node_t *const node)
{
        assert_tree_node(node);

        int result = 1;

        for (const kw_tree_node_t *tmp = node; tmp->parent;
                        tmp = tmp->parent)
                result++;

        return result;
}

int
tree_depth(const kw_tree_t *const tree)
{
        int max_depth = 0;

        for (kw_tree_node_t *node = tree->first;
                        node; node = next_node_in_tree(node))
        {
                const int depth = node_depth(node);
                if (depth > max_depth)
                        max_depth = depth;
        }

        return max_depth;
}



/* vim: set autowrite expandtab: */
