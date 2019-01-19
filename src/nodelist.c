#include <stdlib.h>
#include <stdio.h>

#include "nodelist.h"

/*
 * Can be freed with free()
 */

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

	if (!ex_node->succ)
		ex_node = ex_node->pred;

	new_node->pred = ex_node;
	new_node->succ = ex_node->succ;
	ex_node->succ->pred = new_node;
	ex_node->succ = new_node;
}

void
insert_node_before(kw_node_t *ex_node, kw_node_t *new_node)
{
	if (!ex_node || !new_node)
		return;

	if (!ex_node->pred)
		ex_node = ex_node->succ;

	new_node->pred = ex_node->pred;
	new_node->succ = ex_node;
	ex_node->pred->succ = new_node;
	ex_node->pred = new_node;
}

void
remove_node(kw_node_t *node)
{
	if (!node->pred || !node->succ)
		return;

	node->pred->succ = node->succ;
	node->succ->pred = node->pred;
}

void
add_head(kw_list_t *list, kw_node_t *node)
{
	if (!list || !node)
		return;

	node->succ = list->head.succ;
	node->pred = (kw_node_t *) &list->head;
	list->head.succ = node;
	node->succ->pred = node;
}

void
add_tail(kw_list_t *list, kw_node_t *node)
{
	if (!list || !node)
		return;

	node->succ = (kw_node_t *) &list->tail;
	node->pred = list->tail.pred;
	list->tail.pred = node;
	node->pred->succ = node;
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
	kw_node_t *result;

	if (is_list_empty(list))
		return NULL;

	result = list->head.succ;
	list->head.succ = result->succ;
	result->succ->pred = (kw_node_t *) &list->head;

	return result;

}

kw_node_t *
rem_tail(kw_list_t *list)
{
	kw_node_t *result;

	if (is_list_empty(list))
		return NULL;

	result = list->tail.pred;
	list->tail.pred = result->pred;
	result->pred->succ = (kw_node_t *) &list->tail;

	return result;
}

kw_node_t *
get_list_iterator(kw_list_t *list)
{
	return (kw_node_t *) &list->head;
}

kw_node_t *
get_next_node(kw_node_t **iterator)
{
	*iterator = (*iterator)->succ;

	if ((*iterator)->succ == NULL)
		return NULL;

	return *iterator;
}

void
free_list(kw_list_t *list)
{
	kw_node_t *node = list->head.succ;

	while (node->succ)
	{
		kw_node_t *tmp = node;
		node = node->succ;
		free(tmp);
	}

	free(list);
}

typedef struct foo_s {
	kw_node_t node;
	char *text;
} foo_t;

unsigned int
list_length(kw_list_t *list)
{
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
}

