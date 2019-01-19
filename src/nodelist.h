#ifndef __nodelist_h
#define __nodelist_h

/*
 * functions missing
 *
 * enqueue
 * findname
 */

typedef struct kw_node_s kw_node_t;

typedef struct kw_node_s {
	kw_node_t *succ;
	kw_node_t *pred;
	int pri;
	char *name;
} kw_node_t;

typedef struct kw_list_s {
	kw_node_t head;
	kw_node_t tail;
	/*kw_node_t *head_succ;
	kw_node_t *head_pred;
	kw_node_t *tail_succ;
	kw_node_t *tail_pred;*/
} kw_list_t;

typedef void * kw_iterator;

#define is_list_empty(x) \
	( ((x)->tail.pred) == (kw_node_t *)(x) )

void testerli(void);

kw_list_t * create_list(void);

void add_head(kw_list_t *list, kw_node_t *node);

void add_tail(kw_list_t *list, kw_node_t *node);

kw_node_t *get_list_iterator(kw_list_t *list);

kw_node_t *get_next_node(kw_node_t **iterator);

unsigned int list_length(kw_list_t *list);

kw_node_t * get_head(kw_list_t *list);

void insert_node_before(kw_node_t *ex_node, kw_node_t *new_node);

void remove_node(kw_node_t *node);


#endif /* __nodelist_h */
