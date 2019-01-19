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
#include <err.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>

//#include "xalloc.h"

#include "logactiond.h"

extern bool run_in_foreground;

static char message_buffer[1000];

void xfree(void *ptr)
{
	la_debug("FREED %u\n", ptr);
	free(ptr);
}

static void
stderr_or_syslog(int priority, char *message)
{
	if (priority >= log_level)
		return;

	if (run_in_foreground)
		fprintf(stderr, "<%u>%s", priority, message);
	else
		syslog(priority, message);
}

void
la_debug(char *fmt, ...)
{
#ifndef NDEBUG
	va_list myargs;

	va_start(myargs, fmt);
	vsnprintf(message_buffer, 999, fmt, myargs);
	va_end(myargs);

	stderr_or_syslog(LOG_VDEBUG, message_buffer);
#endif /* NDEBUG */
}

void
la_log_errno(int priority, char *fmt, ...)
{
	va_list myargs;

	va_start(myargs, fmt);
	int len = vsnprintf(message_buffer, 999, fmt, myargs);
	va_end(myargs);
	snprintf(message_buffer+len, 1000-len, ": %s\n", strerror(errno));
	stderr_or_syslog(LOG_ERR, message_buffer);
}

void
la_log(int priority, char *fmt, ...)
{
	va_list myargs;

	va_start(myargs, fmt);
	vsnprintf(message_buffer, 999, fmt, myargs);
	va_end(myargs);

	stderr_or_syslog(priority, message_buffer);
}

void
die_syntax(void)
{
	snprintf(message_buffer, 999, "%s:%d - %s\n",
			config_error_file(&la_config->config_file),
			config_error_line(&la_config->config_file),
			config_error_text(&la_config->config_file));
	stderr_or_syslog(LOG_ERR, message_buffer);

	unload_la_config();
	exit(EXIT_FAILURE);
}

void
die_semantic(char *fmt, ...)
{
	va_list myargs;

	va_start(myargs, fmt);
	vsnprintf(message_buffer, 999, fmt, myargs);
	va_end(myargs);
	stderr_or_syslog(LOG_ERR, message_buffer);

	unload_la_config();
	exit(EXIT_FAILURE);

}

void
die_hard(char *fmt, ...)
{
	va_list myargs;

	va_start(myargs, fmt);
	vsnprintf(message_buffer, 999, fmt, myargs);
	va_end(myargs);
	vfprintf(stderr, fmt, myargs);
	stderr_or_syslog(LOG_ERR, message_buffer);

	unload_la_config();
	exit(EXIT_FAILURE);
}

void
die_err(char *fmt, ...)
{
	va_list myargs;
	va_start(myargs, fmt);
	int len = vsnprintf(message_buffer, 999, fmt, myargs);
	va_end(myargs);
	snprintf(message_buffer+len, 1000-len, ": %s\n", strerror(errno));
	stderr_or_syslog(LOG_ERR, message_buffer);
	exit(EXIT_FAILURE);
}

void *
xmalloc(size_t n)
{
	void *result =  malloc(n);
	if (!result && n!=0)
		die_hard("Memory exhausted\n");

	return result;
}

char *
xstrdup(const char *s)
{
	void *result = strdup(s);
	if (!result)
		die_hard("Memory exhausted\n");

	return result;
}

char *
xstrndup(const char *s, size_t n)
{
	void *result = strndup(s, n);
	if (!result)
		die_hard("Memory exhausted\n");

	return result;
}

/* vim: set autowrite expandtab: */
