#include <config.h>

#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/inotify.h>
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
