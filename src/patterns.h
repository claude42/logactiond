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

#ifndef __patterns_h
#define __patterns_h

#include <regex.h>

#include "ndebug.h"
#include "properties.h"

#define ITERATE_PATTERNS(PATTERNS) (la_pattern_t *) &(PATTERNS)->head
#define NEXT_PATTERN(PATTERN) (la_pattern_t *) (PATTERN->node.succ->succ ? PATTERN->node.succ : NULL)
#define HAS_NEXT_PATTERN(PATTERN) PATTERN->node.succ
#define REM_PATTERNS_HEAD(PATTERNS) (la_pattern_t *) rem_head(PATTERNS)

#ifdef NDEBUG
#define assert_pattern(PATTERN) (void)(0)
#else /* NDEBUG */
#define assert_pattern(PATTERN) assert_pattern_ffl(PATTERN, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

typedef struct la_pattern_s
{
        kw_node_t node;
        int num; // position of the pattern in the config file
        struct la_rule_s *rule;
        char *string; /* already converted regex, doesn't contain tokens anymore */
        regex_t regex; /* compiled regex */
        la_property_t *host_property;
        kw_list_t *properties; /* list of la_property_t */
        long int detection_count;
        long int invocation_count;
} la_pattern_t;

void assert_pattern_ffl(const la_pattern_t *pattern, const char *func,
                const char *file, int line);

la_pattern_t *create_pattern(const char *string_from_configfile, int num,
                la_rule_t *rule);

void free_pattern(la_pattern_t *pattern);

void free_pattern_list(kw_list_t *list);

#endif /* __patterns_h */

/* vim: set autowrite expandtab: */
