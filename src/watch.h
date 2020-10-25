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

#ifndef __watch_h
#define __watch_h

#include "ndebug.h"
#include "sources.h"

extern pthread_t file_watch_thread;

void watch_source(la_source_t *source, int whence);

void unwatch_source(la_source_t *source);

void init_watching(void);

void start_watching_threads(void);

void shutdown_watching(void);

#endif /* __watch_h */

/* vim: set autowrite expandtab: */
