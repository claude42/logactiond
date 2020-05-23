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

#ifndef __status_h
#define __status_h

#include <config.h>

#include "ndebug.h"
#include "logactiond.h"

#define HOSTSFILE RUNDIR "/logactiond.hosts"
#define RULESFILE RUNDIR "/logactiond.rules"
#define DIAGFILE RUNDIR "/logactiond.diagnostics"

extern pthread_t monitoring_thread;

void start_monitoring_thread(void);

void dump_rules(void);

void dump_queue_status(bool force);

#endif /* __status_h */

/* vim: set autowrite expandtab: */