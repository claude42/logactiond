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

#ifndef logging_h
#define logging_h

#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdnoreturn.h>

#include <config.h>

#include "ndebug.h"

#define LOG_RETURN(retval, ...) do { la_log(__VA_ARGS__); return retval; } while (0)
#define LOG_RETURN_VERBOSE(retval, ...) do { la_log_verbose(__VA_ARGS__); return retval; } while (0)
#define LOG_RETURN_ERRNO(retval, ...) do { la_log_errno(__VA_ARGS__); return retval; } while (0)

#define SYSLOG_IDENT PACKAGE

// verbose debugging loglevel
#define LOG_VDEBUG (LOG_DEBUG+1)

extern int log_level;

extern bool log_verbose;

#define la_debug(...) log_message(LOG_DEBUG, NULL, __VA_ARGS__)
#define la_vdebug(...) log_message(LOG_VDEBUG, NULL, __VA_ARGS__)
#define la_log_errno(PRIORITY, ...) log_message(PRIORITY, strerror(errno), __VA_ARGS__)
#define la_log_verbose(PRIORITY, ...) if (log_verbose) log_message(PRIORITY, NULL, __VA_ARGS__)
#define la_log(PRIORITY, ...) log_message(PRIORITY, NULL, __VA_ARGS__)
#define la_debug_func(PARAMS) log_message(LOG_DEBUG, NULL, "%s(%s)", __func__, PARAMS ? PARAMS : "")
#define la_vdebug_func(PARAMS) log_message(LOG_VDEBUG, NULL, "%s(%s)", __func__, PARAMS ? PARAMS : "")

#ifdef NDEBUG
#define assert(CONDITION) (void)(0)
#else /* NDEBUG */
#define assert(CONDITION) if (!(CONDITION)) assert_failed(#CONDITION, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

/* The following needs more work */
#if 0
#ifdef CLIENTONLY
#define die_hard(LOG_STRERROR, ...) \
        do { \
                log_message(LOG_ERR, LOG_STRERROR ? strerror(errno) : NULL, __VA_ARGS__); \
                exit(1); \
        } while (0)
#else /* CLIENTONLY */
#define die_hard(LOG_STRERROR, ...) \
        do { \
                int save_errno = errno; \
                log_message(LOG_ERR, LOG_STRERROR ? strerror(errno) : NULL, __VA_ARGS__); \
                if (!shutdown_ongoing) \
                        trigger_shutdown(EXIT_FAILURE, save_errno); \
                pthread_exit(NULL); \
        } while (0)
#endif /* CLIENTONLY */
#endif

void log_message(int priority, const char *add, const char *fmt, ...);

void log_message_va_list(int priority, const char *fmt, va_list gp, const char *add);

void assert_failed(const char *condition, const char *func, const char *file,
                int line);

noreturn void die_hard(bool log_strerror, const char *fmt, ...);

#endif /* logging_h */

/* vim: set autowrite expandtab: */
