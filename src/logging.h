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

#include <config.h>

#include "ndebug.h"

#define SYSLOG_IDENT PACKAGE

// verbose debugging loglevel
#define LOG_VDEBUG (LOG_DEBUG+1)

void log_message(int priority, const char *fmt, va_list gp, const char *add);

void la_debug(const char *fmt, ...);

void la_vdebug(const char *fmt, ...);

void la_log_errno(int priority, const char *fmt, ...);

void la_log_verbose(int priority, const char *fmt, ...);

void la_log(int priority, const char *fmt, ...);

void die_hard(const char *fmt, ...);

void die_val(int val, const char *fmt, ...);

void die_err(const char *fmt, ...);

#endif /* logging_h */

/* vim: set autowrite expandtab: */
