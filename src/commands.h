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

#ifndef __commands_h
#define __commands_h

#include "ndebug.h"
#include "nodelist.h"
#include "addresses.h"
#include "patterns.h"
#include "binarytree.h"

/* assertions */

#ifdef NDEBUG
#define assert_command(COMMAND) (void)(0)
#else /* NDEBUG */
#define assert_command(COMMAND) assert_command_ffl(COMMAND, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

#define empty_command_list(list) \
        empty_list(list, (void (*)(void *const)) free_command)

#define free_command_list(list) \
        free_list(list, (void (*)(void *const)) free_command)

typedef enum la_commandtype_s { LA_COMMANDTYPE_BEGIN, LA_COMMANDTYPE_END } la_commandtype_t;

typedef enum la_need_host_s { LA_NEED_HOST_NO, LA_NEED_HOST_ANY,
        LA_NEED_HOST_IP4, LA_NEED_HOST_IP6 } la_need_host_t;

typedef enum la_submission_s { LA_SUBMISSION_LOCAL, LA_SUBMISSION_MANUAL,
        LA_SUBMISSION_REMOTE, LA_SUBMISSION_RENEW } la_submission_t;

typedef struct la_command_s la_command_t;
struct la_command_s
{
        struct kw_node_s node;
        kw_tree_node_t adr_node;
        int id;        /* unique id */
        bool is_template;       /* true for templates, false for derived commands */
        char *begin_string;        /* string with tokens */
        char *begin_string_converted;
        struct kw_list_s begin_properties;        /* detected tokens */
        int n_begin_properties;/* number of detected tokens */
        char *end_string;        /* string with tokens */
        char *end_string_converted;
        struct kw_list_s end_properties;        /* detected tokens */
        int n_end_properties;/* number of detected tokens */
        struct la_rule_s *rule;        /* related rule */
        struct la_pattern_s *pattern;        /* related pattern*/
        struct kw_list_s pattern_properties; /* properties from matched pattern */
        struct la_address_s *address;     /* IP address */
        enum la_need_host_s need_host;    /* Command requires host */
        int duration;                /* duration how long command shall stay active,
                                   -1 if none */
        int factor;
        enum la_submission_s submission_type;
        bool previously_on_blacklist;         /* True if command has been triggered via blacklist */
        bool quick_shutdown;

        /* only relevant for end_commands */
        time_t end_time;        /* specific time for enqueued end_commands */
        char *rule_name;

        /* only relevant in trigger_list */
        int n_triggers;/* how man times triggered during period */
        time_t start_time;        /* time of first trigger during period */

};

/* commands.c */

void convert_both_commands(la_command_t *command);

void assert_command_ffl(const la_command_t *command, const char *func,
                const char *file, int line);

void trigger_manual_command(const la_address_t *address,
                const la_command_t *template, time_t end_time, int factor,
                const la_address_t *from_addr, bool suppress_logging);

void trigger_command(la_command_t *command);

void trigger_end_command(const la_command_t *command, bool suppress_logging);

la_command_t * create_command_from_template(const la_command_t *template,
                la_pattern_t *pattern, const la_address_t *address);

la_command_t * create_manual_command_from_template(
                const la_command_t *template, const la_address_t *address,
                const la_address_t *from_addr);

la_command_t *create_template(const char *name, la_rule_t *rule,
                const char *begin_string, const char *end_string,
                int duration, la_need_host_t need_host, bool quick_shutdown);

void free_command(la_command_t *command);

const char *command_address_on_dnsbl(const la_command_t *const command);

#endif /* __commands_h */

/* vim: set autowrite expandtab: */
