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

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#if HAVE_INOTIFY
#include <sys/inotify.h>
#endif /* HAVE_INOTIFY */
#include <sys/select.h>

#include <libconfig.h>

#include "logactiond.h"




/*
 * Abstract event loop
 */

void
watch_forever(void)
{
#if HAVE_INOTIFY
	watch_forever_inotify();
#endif /* HAVE_INOTIFY */
}


/*
 * Do all steps necessary before files can be watched. Depending on the method
 * used, no such steps might be necessary at all.
 */

void
init_watching(void)
{

#if HAVE_INOTIFY
	init_watching_inotify();
#else /* HAVE_INOTIFY */
	die_hard("Don't have inotify");
#endif /* HAVE_INOTIFY */
}

/* vim: set autowrite expandtab: */
