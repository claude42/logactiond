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

#include <config.h>

#include <string.h>
#include <assert.h>

#include "logactiond.h"
#include "nodelist.h"


bool
address_on_ignore_list(const char *ip)
{
        if (!ip)
                return false;

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
        assert(ip);

	la_address_t *result = (la_address_t *) xmalloc(sizeof(la_address_t));

	result->ip = xstrdup(ip);

	return result;
}

/* vim: set autowrite expandtab: */
