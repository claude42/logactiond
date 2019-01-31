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

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <assert.h>

#include "nodelist.h"

#include "logactiond.h"

void
assert_node(kw_node_t *node)
{
        assert(node->succ || node->pred);

        assert (node->succ != node->pred);

        if (node->pred)
                assert (node->pred->succ == node);

        if (node->succ)
                assert (node->succ->pred == node);
}

void
assert_list(kw_list_t *list)
{
        assert(list);
        assert(list->head.succ && list->tail.pred);
        assert(!list->head.pred && !list->tail.succ);

        for (kw_node_t *node = list->head.succ; node->succ; node = node->succ)
        {
                assert_node(node);
        }
}


/*
 * Can be freed with free()
 */

/* TODO: we need a xcreate_list() as well */

kw_list_t *
create_list(void)
{
	kw_list_t *result = (kw_list_t *) malloc(sizeof (kw_list_t));
	if (!result)
	{
		fprintf(stderr, "Memory exhausted\n");
		exit(EXIT_FAILURE);
	}

	result->head.succ = (kw_node_t *) &result->tail;
	result->head.pred = NULL;
	result->tail.succ = NULL;
	result->tail.pred = (kw_node_t *) &result->head;

        assert_list(result);

	return result;
}

/*
 * When new_node == list->head, new_node is inserted at the beginning of the list.
 * Wenn new_node == list->tail, new_node is inserted at the end of the list
 */

void
insert_node_after(kw_node_t *ex_node, kw_node_t *new_node)
{
	if (!ex_node || !new_node)
		return;

        assert_node(ex_node);

	if (!ex_node->succ)
		ex_node = ex_node->pred;

        kw_node_t *succ = ex_node->succ;

	new_node->pred = ex_node;
	new_node->succ = ex_node->succ;
	ex_node->succ->pred = new_node;
	ex_node->succ = new_node;

        assert_node(new_node); assert_node(ex_node); assert_node(succ);
}


void
insert_node_before(kw_node_t *ex_node, kw_node_t *new_node)
{
        if (!ex_node || !new_node)
                return;

        assert_node(ex_node);

	if (!ex_node->pred)
		ex_node = ex_node->succ;

        kw_node_t *pred = ex_node->pred;

	new_node->pred = ex_node->pred;
	new_node->succ = ex_node;
	ex_node->pred->succ = new_node;
	ex_node->pred = new_node;

        assert_node(new_node); assert_node(ex_node); assert_node(pred);
}

void
remove_node(kw_node_t *node)
{
	if (!node->pred || !node->succ)
		return;

        assert_node(node);

	node->pred->succ = node->succ;
	node->succ->pred = node->pred;

        assert_node(node->pred); assert_node(node->succ);
}

void
add_head(kw_list_t *list, kw_node_t *node)
{
	if (!list || !node)
		return;

        assert_list(list);

	node->succ = list->head.succ;
	node->pred = (kw_node_t *) &list->head;
	list->head.succ = node;
	node->succ->pred = node;

        assert_list(list); assert_node(node);
}

void
add_tail(kw_list_t *list, kw_node_t *node)
{
	if (!list || !node)
		return;

        assert_list(list);

	node->succ = (kw_node_t *) &list->tail;
	node->pred = list->tail.pred;
	list->tail.pred = node;
	node->pred->succ = node;

        assert_list(list); assert_node(node);
}

kw_node_t *
get_head(kw_list_t *list)
{
	/* TODO: something's wrong here */
	if (is_list_empty(list))
		return NULL;

	return list->head.succ;
}

kw_node_t *
get_tail(kw_list_t *list)
{
	if (is_list_empty(list))
		return NULL;

	return list->tail.pred;
}

kw_node_t *
rem_head(kw_list_t *list)
{
        assert_list(list);

	kw_node_t *result;

	if (is_list_empty(list))
		return NULL;

	result = list->head.succ;
	list->head.succ = result->succ;
	result->succ->pred = (kw_node_t *) &list->head;

        assert_list(list);

	return result;

}

kw_node_t *
rem_tail(kw_list_t *list)
{
        assert_list(list);

	kw_node_t *result;

	if (is_list_empty(list))
		return NULL;

	result = list->tail.pred;
	list->tail.pred = result->pred;
	result->pred->succ = (kw_node_t *) &list->tail;

        assert_list(list);

	return result;
}

kw_node_t *
get_list_iterator(kw_list_t *list)
{
        assert_list(list);

	return (kw_node_t *) &list->head;
}

kw_node_t *
get_next_node(kw_node_t **iterator)
{
        assert_node(*iterator);
        
	*iterator = (*iterator)->succ;

        assert_node(*iterator);

	if ((*iterator)->succ == NULL)
		return NULL;

	return *iterator;
}

void
free_list(kw_list_t *list)
{
        assert_list(list);

	kw_node_t *node = list->head.succ;

	while (node->succ)
	{
		kw_node_t *tmp = node;
		node = node->succ;
		free(tmp);
	}

	free(list);
}

unsigned int
list_length(kw_list_t *list)
{
        assert_list(list);

	kw_node_t *node = list->head.succ;
	unsigned int result = 0;

	while (node->succ)
	{
		result++;
		node = node->succ;
	}

	return result;
}

/*
 * &mylist->head = pointer auf list header
 * mylist->head.succ = pointer auf next element (list footer bei empty list)
 * mylist->head.pred = null
 * &mylist->tail = pointer auf footer
 * mylist->tail.succ
 *
 * Don't use mylist->head / mylist->tail
 */

/*
typedef struct foo_s {
	kw_node_t node;
	char *text;
} foo_t;

void testerli(void)
{
	kw_list_t *mylist = create_list();
	printf("mylist=%u\n", mylist);
	printf("&mylist->head=%u\n", &mylist->head);
	printf("mylist->head.succ=%u\n", mylist->head.succ);
	printf("mylist->head.pred=%u\n", mylist->head.pred);
	printf("mylist->head.succ->pred=%u\n", mylist->head.succ->pred);
	printf("&mylist->tail=%u\n", &mylist->tail);
	printf("mylist->tail.succ=%u\n", mylist->tail.succ);
	printf("mylist->tail.pred=%u\n", mylist->tail.pred);
	printf("---\n");

	foo_t *result = (foo_t *) malloc(sizeof(foo_t));
	result->text = "bla";

	add_tail(mylist, (kw_node_t *) result);

	printf("mylist=%u\n", mylist);
	printf("&mylist->head=%u\n", &mylist->head);
	printf("mylist->head.succ=%u\n", mylist->head.succ);
	printf("mylist->head.pred=%u\n", mylist->head.pred);
	printf("result=%u\n", result);
	printf("result->node.succ=%u\n", result->node.succ);
	printf("result->node.pred=%u\n", result->node.pred);
	printf("mylist->head.succ->pred=%u\n", mylist->head.succ->pred);
	printf("&mylist->tail=%u\n", &mylist->tail);
	printf("mylist->tail.succ=%u\n", mylist->tail.succ);
	printf("mylist->tail.pred=%u\n", mylist->tail.pred);
	printf("---\n");

	result = (foo_t *) malloc(sizeof(foo_t));
	result->text = "blub";

	add_tail(mylist, (kw_node_t *) result);

	result = (foo_t *) get_head(mylist);
	printf("get_head=%s\n", result->text);

	kw_node_t *i = get_list_iterator(mylist);
	while (result = (foo_t *) get_next_node(&i))
		printf("loop1: %s\n", result->text); 

	result = (foo_t *) rem_head(mylist);
	printf("4: %s\n", result->text);
	free(result);
	printf("Still there\n");

	printf("isempty=%u\n", is_list_empty(mylist));

	remove_node(get_tail(mylist));

	printf("isempty=%u\n", is_list_empty(mylist));
	

	free_list(mylist);
	printf("Still there\n");
}*/


/* vim: set autowrite expandtab: */
