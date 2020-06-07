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

#ifndef __logactiond_h
#define __logactiond_h

#include <stdbool.h>
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */

#include <config.h>

#if HAVE_RUN
#define RUNDIR "/run"
#else
#define RUNDIR "/var/run"
#endif

#define DEFAULT_PORT_STR "16473"

// buffer size for reading log lines
#define DEFAULT_LINEBUFFER_SIZE 1024

typedef enum la_runtype_s la_runtype_t;
enum la_runtype_s { LA_DAEMON_BACKGROUND, LA_DAEMON_FOREGROUND,
        LA_UTIL_FOREGROUND };

/* Global variables */

extern unsigned int log_level;

extern bool log_verbose;

extern unsigned int id_counter;

extern la_runtype_t run_type;

extern unsigned int status_monitoring;

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
        extern atomic_bool shutdown_ongoing;
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
        extern bool shutdown_ongoing;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */

extern int exit_status;

/* logactiond.c */

void trigger_shutdown(int status, int saved_errno);

void trigger_reload(void);

#endif /* __logactiond_h */

/* vim: set autowrite expandtab: */
