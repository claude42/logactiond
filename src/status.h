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

#ifndef __status_h
#define __status_h

#include <config.h>

#include "ndebug.h"

#define RULES_HEADER \
        "En Rule          Service       Source        Detected  Invoked  In queue\n" \
        "========================================================================\n"

/* Parameters: enabled, name, service, source, detection count, invocation
 * count, queue count */
#define RULES_LINE "%c  %-13.13s %-13.13s %-13.13s %8lu %8lu %8lu\n"

#define HOSTS_HEADER \
        "%s\n\nIP address                                  Ma Fa Time Rule          Action\n" \
        "===============================================================================\n"

/* Parameters: address, type, factor, timedelta, unit, rule name, command name
 */
#define HOSTS_LINE "%-43.43s %s %2d %2ld%c  %-13.13s %-13.13s\n"
#define HOSTS_LINE_V "%-43.43s %s %2d %2ld%c  %-13.13s %-13.13s (%u,%u)\n"

extern pthread_t monitoring_thread;

void start_monitoring_thread(void);

void dump_rules(void);

void dump_queue_status(bool force);

#endif /* __status_h */

/* vim: set autowrite expandtab: */
