#include <config.h>

//#include <regex.h>
//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
//#include <sys/inotify.h>
//#include <sys/select.h>
#include <assert.h>

#include "logactiond.h"
#include "nodelist.h"


bool
address_on_ignore_list(const char *ip)
{
	assert(ip);

	for (la_address_t *address = (la_address_t *) la_config->ignore_addresses->head.succ;
			address->node.succ;
			address = (la_address_t *) address->node.succ)
	{
		if (!strcmp(address->ip, ip))
			return true;
	}

	return false;
}

la_address_t *
create_address(const char *ip)
{
	la_address_t *result = (la_address_t *) xmalloc(sizeof(la_address_t));

	result->ip = ip;

	return result;
}
