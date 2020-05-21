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

#ifndef __systemd_h
#define __systemd_h

#include <config.h>

#include "ndebug.h"

// systemd_source
#if HAVE_LIBSYSTEMD
#define SYSTEMD_SOURCE (la_source_t *) la_config->systemd_source_group->sources->head.succ

extern pthread_t systemd_watch_thread;

/* systemd.c */

void init_watching_systemd(void);

void start_watching_systemd_thread(void);

void add_systemd_unit(const char *systemd_unit);

#endif /* HAVE_LIBSYSTEMD */

#endif /* __systemd_h */

/* vim: set autowrite expandtab: */
