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

#ifndef __logactiond_h
#define __logactiond_h

#include <stdbool.h>
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
#include <pthread.h>

#include <config.h>

/* Configuration directory and main config file */

#if !defined(CONF_DIR)
#define CONF_DIR "/etc/logactiond"
#endif /* !defined(CONF_DIR) */

#define CONFIG_FILE "logactiond.cfg"

/* State directory and file */

#if !defined(STATE_DIR)
#define STATE_DIR "/var/lib/logactiond"
#endif /* !defined(STATE_DIR) */

#define STATE_FILE "logactiond.state"
#define BAK_SUFFIX ".bak"
#define HOSTSFILE STATE_DIR "/logactiond.hosts"
#define RULESFILE STATE_DIR "/logactiond.rules"
#define DIAGFILE STATE_DIR "/logactiond.diagnostics"

/* Run directory */

#if !defined(RUN_DIR)
#define RUN_DIR "/var/run"
#endif

#define FIFOFILE RUN_DIR "/logactiond.fifo"
#define PIDFILE RUN_DIR "/logactiond.pid"

#define DEFAULT_PORT_STR "16473"

// buffer size for reading log lines
#define DEFAULT_LINEBUFFER_SIZE 1024

typedef enum la_runtype_s { LA_DAEMON_BACKGROUND, LA_DAEMON_FOREGROUND,
        LA_UTIL_FOREGROUND } la_runtype_t;

/* Global variables */

extern la_runtype_t run_type;

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
        extern atomic_bool shutdown_ongoing;
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
        extern bool shutdown_ongoing;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */

/* logactiond.c */

void trigger_shutdown(int status, int saved_errno);

void trigger_reload(void);

void thread_started(pthread_t thread);

void wait_final_barrier(void);

#endif /* __logactiond_h */

/* vim: set autowrite expandtab: */
