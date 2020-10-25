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

#ifndef __rules_h
#define __rules_h

#include "ndebug.h"
#include "addresses.h"
#include "sources.h"
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */

// maximum number of tokens that can be matched

#define MAX_NMATCH 20

#define ITERATE_RULES(RULES) (la_rule_t *) &(RULES)->head
#define NEXT_RULE(RULE) (la_rule_t *) (RULE->node.succ->succ ? RULE->node.succ : NULL)
#define HAS_NEXT_RULE(RULE) RULE->node.succ
#define REM_RULES_HEAD(RULES) (la_rule_t *) rem_head(RULES)

#ifdef NDEBUG
#define assert_rule(RULE) (void)(0)
#else /* NDEBUG */
#define assert_rule(RULE) assert_rule_ffl(RULE, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

typedef struct la_rule_s la_rule_t;
struct la_rule_s
{
        struct kw_node_s node;
        bool enabled;
        char *name;
        int id;
        struct la_source_group_s *source_group;
        char *service;
        struct kw_list_s *patterns;
        struct kw_list_s *begin_commands;
        int threshold;
        int period;
        int duration;
        bool meta_enabled;
        int meta_period;
        int meta_factor;
        int meta_max;
        char *systemd_unit;
        struct kw_list_s *trigger_list;
        struct kw_list_s *properties;
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
        atomic_long detection_count;
        atomic_long invocation_count;
        atomic_long queue_count;
#else /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
        long int detection_count;
        long int invocation_count;
        long int queue_count;
#endif /* __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__) */
        bool dnsbl_enabled;
        struct kw_list_s *blacklists;
};

void assert_rule_ffl(const la_rule_t *rule, const char *func, const char *file,
                int line);

void handle_log_line_for_rule(const la_rule_t *rule, const char *line);

void trigger_manual_commands_for_rule(const la_address_t *address, const
                la_rule_t *rule, time_t end_time, int factor, const char *from,
                bool suppress_logging);

la_rule_t *create_rule(bool enabled, const char *name, la_source_group_t
                *source_group, int threshold, int period, int duration,
                int meta_enabled, int meta_period, int meta_factor,
                int meta_max, int dnsbl_enabled, const char *service,
                const char *systemd_unit);

void free_rule(la_rule_t *rule);

void free_rule_list(kw_list_t *list);

la_rule_t *find_rule(const char *rule_name);

#endif /* __rules_h */

/* vim: set autowrite expandtab: */
