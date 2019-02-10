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


#include <config.h>

#include <sys/select.h>
#include <regex.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>

#include <libconfig.h>

#include "nodelist.h"



//#define NDEBUG

//#define CONF_DIR "/etc/logactiond"
#define CONFIG_FILE "logactiond.cfg"

// one level above LOG_DEBUG
#define LOG_VDEBUG LOG_DEBUG+1



#define LA_DEFAULTS_LABEL "defaults"

#define LA_PROPERTIES_LABEL "properties"

#define LA_THRESHOLD_LABEL "threshold"
#define LA_PERIOD_LABEL "period"
#define LA_DURATION_LABEL "duration"


#define LA_ACTIONS_LABEL "actions"
#define LA_ACTION_INITIALIZE_LABEL "initialize"
#define LA_ACTION_SHUTDOWN_LABEL "shutdown"
#define LA_ACTION_BEGIN_LABEL "begin"
#define LA_ACTION_END_LABEL "end"

#define LA_SOURCES_LABEL "sources"

#define LA_LOCAL_LABEL "local"
#define LA_LOCAL_ENABLED_LABEL "enabled"

#define LA_RULES_LABEL "rules"
#define LA_RULE_SOURCE_LABEL "source"
#define LA_RULE_TYPE_LABEL "type"
#define LA_RULE_TYPE_FILE_OPTION "file"
#define LA_RULE_TYPE_SYSTEMD_OPTION "systemd"
#define LA_RULE_ACTION_LABEL "action"
#define LA_RULE_PATTERNS_LABEL "pattern"

#define LA_LOCATION "location"

#define LA_TOKEN_REPL "(.+)"
#define LA_TOKEN_REPL_LEN 4

#define LA_HOST_TOKEN "host"
#define LA_HOST_TOKEN_REPL "([.:[:xdigit:]]+)"
#define LA_HOST_TOKEN_REPL_LEN 17

#define LA_RULENAME_TOKEN "rulename"
#define LA_SOURCENAME_TOKEN "sourcename"
#define LA_PATTERNNAME_TOKEN "patternname"

// maximum number of tokens that can be matched

#define MAX_NMATCH 20

// buffer size for reading log lines
#define DEFAULT_LINEBUFFER_SIZE 8192

/* List macros */

#define ITERATE_ADDRESSES(ADDRESSES) (la_address_t *) &ADDRESSES->head
#define NEXT_ADDRESS(ADDRESS) (la_address_t *) (ADDRESS->node.succ->succ ? ADDRESS->node.succ : NULL)

#define ITERATE_COMMANDS(COMMANDS) (la_command_t *) &COMMANDS->head
#define NEXT_COMMAND(COMMAND) (la_command_t *) (COMMAND->node.succ->succ ? COMMAND->node.succ : NULL)
#define HAS_NEXT_COMMAND(COMMAND) COMMAND->node.succ

#define ITERATE_PATTERNS(PATTERNS) (la_pattern_t *) &PATTERNS->head
#define NEXT_PATTERN(PATTERN) (la_pattern_t *) (PATTERN->node.succ->succ ? PATTERN->node.succ : NULL)

#define ITERATE_PROPERTIES(PROPERTIES) (la_property_t *) &PROPERTIES->head
#define NEXT_PROPERTY(PROPERTY) (la_property_t *) (PROPERTY->node.succ->succ ? PROPERTY->node.succ : NULL)
#define HAS_NEXT_PROPERTY(PROPERTY) PROPERTY->node.succ

#define ITERATE_RULES(RULES) (la_rule_t *) &RULES->head
#define NEXT_RULE(RULE) (la_rule_t *) (RULE->node.succ->succ ? RULE->node.succ : NULL)

#define ITERATE_SOURCES(SOURCES) (la_source_t *) &SOURCES->head
#define NEXT_SOURCE(SOURCE) (la_source_t *) (SOURCE->node.succ->succ ? SOURCE->node.succ : NULL)

/* Types */

typedef struct la_source_s la_source_t;
typedef struct la_rule_s la_rule_t;
typedef struct la_command_s la_command_t;

// TODO: add default type
typedef enum la_sourcetype_s { LA_RULE_TYPE_FILE, LA_RULE_TYPE_SYSTEMD } la_sourcetype_t;

typedef enum la_commandtype_s { LA_COMMANDTYPE_BEGIN, LA_COMMANDTYPE_END } la_commandtype_t;

typedef enum la_runtype_s { LA_DAEMON_BACKGROUND, LA_DAEMON_FOREGROUND,
        LA_UTIL_FOREGROUND, LA_UTIL_DEBUG } la_runtype_t;

/*
 * bla
 */

typedef struct la_address_s
{
        kw_node_t node;
        struct in_addr addr;
        int prefix;
} la_address_t;

/*
 * bla
 *
 * name - name of property: strdup()d
 * value - value of property: strdup()d
 *
 * Note: both name and value must be assigned strdup()ed strings
 *
 * XXX: in it's current implementation, la_property_t data structure is not
 * thread safe. I.e. the same pattern must not be used by different backend (as
 * these run in different threads).
 */

typedef struct la_property_s
{
        kw_node_t node;
        /* name of the property (for matched tokens: without '<' and '>') */
        char *name;
        /* Property created from HOST token */
        bool is_host_property;
        /* Different uses:
         * - when used for config file properties, this is simply the value
         *   assigned to the property in the config file
         * - when used when matching a log line to a regex, this is the matched
         *   value from the log line
         * - when used as an action token, this is the value taken from the
         *   original token
         *
         * XXX: Not thread-safe: i.e. using the same pattern for different
         * backends will not work.
         * BTW: strings will be strdup()ed - take care to free again */
        char *value;

        /* The following  members will only be used when properties are
         * obtained from log lines matching tokens or in action strings.
         */

        /* Position in original string. Points to innitial '<'!.
         * Only for use in convert_regex() */
        unsigned int pos;
        /* Length of token including '<' and '>'. Save us a few strlen() calls in
         * convert_regex()... */
        size_t length;

        /* The following members will only be used when matching log lines.  */

        /* Number of the subexpression this token represents in the regular
         * expression.
         */
        unsigned int subexpression;
} la_property_t;

typedef struct la_pattern_s
{
        kw_node_t node;
        unsigned int num;
        la_rule_t *rule;
        const char *string; /* already converted regex, doesn't contain tokens anymore */
        regex_t *regex; /* compiled regex */
        kw_list_t *properties; /* list of la_property_t */
} la_pattern_t;

typedef struct la_rule_s
{
        kw_node_t node;
        char *name;
        la_source_t *source;
        kw_list_t *patterns;
        kw_list_t *begin_commands;
        unsigned int threshold;
        unsigned int period;
        unsigned int duration;
        kw_list_t *trigger_list;
        kw_list_t *properties;
} la_rule_t;

typedef struct la_command_s
{
        kw_node_t node;
        unsigned int id;        /* unique id */
        char *begin_string;        /* string with tokens */
        kw_list_t *begin_properties;        /* detected tokens */
        unsigned int n_begin_properties;/* number of detected tokens */
        char *end_string;        /* string with tokens */
        kw_list_t *end_properties;        /* detected tokens */
        unsigned int n_end_properties;/* number of detected tokens */
        la_rule_t *rule;        /* related rule */
        la_pattern_t *pattern;        /* related pattern*/
        kw_list_t *pattern_properties; /* properties from matched pattern */
        struct in_addr addr;     /* IP address */
        char *host;                /* IP address */
        int duration;                /* duration how long command shall stay active,
                                   -1 if none */

        /* only relevant for end_commands */
        time_t end_time;        /* specific time for enqueued end_commands */

        /* only relevant in trigger_list */
        unsigned int n_triggers;/* how man times triggered during period */
        time_t start_time;        /* time of first trigger during period */

} la_command_t;

/*
 * Represents a source
 */

typedef struct la_source_s
{
        kw_node_t node;
        /* Name of source in config file - strdup()d */
        const char *name;
        la_sourcetype_t type;
        /* Filename (or equivalent) - strdup()d */
        const char *location;
        /* Parent dir of log file - currently only used for inotify */
        const char *parent_dir;
        /* Rules assigned to log file */
        kw_list_t *rules;
        /* File handle for log file */
        FILE *file;
#if HAVE_INOTIFY
        /* Watch descriptor for log file itself */
        int wd;
        /* Watch descriptor for parent directory */
        int parent_wd;
#endif /* HAVE_INOTIFY */

} la_source_t;

typedef struct la_config_s
{
        config_t config_file;
        kw_list_t *sources;
        int default_threshold;
        int default_period;
        int default_duration;
        kw_list_t *default_properties;
        kw_list_t *ignore_addresses;
} la_config_t;

/* Global variables */

extern la_config_t *la_config;

extern unsigned int log_level;

extern unsigned int id_counter;

/* Functions */

/* misc.c */

void xfree (void *ptr);

void la_debug(char *fmt, ...);

void la_log_errno(int priority, char *fmt, ...);

void la_log(int priority, char *fmt, ...);

void die_semantic(char *fmt, ...);

void die_hard(char *fmt, ...);

void die_err(char *fmt, ...);

void *xmalloc(size_t n);

char *xstrdup(const char *s);

char *xstrndup(const char *s, size_t n);

/* configfile.c */

void load_la_config(char *filename);

void unload_la_config(void);

/* addresses.c */

struct in_addr string_to_addr(const char *host);

char *addr_to_string(struct in_addr addr);

bool address_on_ignore_list(struct in_addr addr);

la_address_t *create_address(const char *ip);

/* endqueue.c */

la_command_t *find_end_command(la_rule_t *rule, struct in_addr addr);

void empty_end_queue(void);

void enqueue_end_command(la_command_t *end_command);

void init_end_queue(void);

/* commands.c */

void assert_command(la_command_t *command);

void trigger_command(la_command_t *command);

void trigger_end_command(la_command_t *command);

la_command_t * dup_command(la_command_t *command);

la_command_t * create_command_from_template(la_command_t *template,
                la_rule_t *rule, la_pattern_t *pattern, struct in_addr addr);

la_command_t *create_template(la_rule_t *rule, const char *begin_string,
                const char *end_string, int duration);

void free_command(la_command_t *command);

/* properties.c */

void assert_property(la_property_t *property);

size_t token_length(const char *string);

size_t scan_single_token(kw_list_t *property_list, const char *string,
                unsigned int pos, unsigned int subexpression);

const char *get_host_property_value(kw_list_t *property_list);

la_property_t *get_property_from_property_list(kw_list_t *property_list,
                const char *name);

const char *get_value_from_property_list(kw_list_t *property_list,
                la_property_t *property);

la_property_t *create_property_from_config(const char *name, const char *value);

la_property_t *create_property_from_action_token(const char *name, size_t length,
                unsigned int pos);

la_property_t *create_property_from_token(const char *name, size_t length, unsigned
                int pos, unsigned int subexpression);

kw_list_t *dup_property_list(kw_list_t *list);

void free_property(la_property_t *property);

void free_property_list(kw_list_t *list);

/* patterns.c */

void assert_pattern(la_pattern_t *pattern);

la_pattern_t *create_pattern(const char *string_from_configfile,
                unsigned int num, la_rule_t *rule);

/* rules.c */

void assert_rule(la_rule_t *rule);

void handle_log_line_for_rule(la_rule_t *rule, char *line);

la_rule_t * create_rule(char *name, la_source_t *source, int threshold,
                int period, int duration);

/* sources.c */

void assert_source(la_source_t *source);

void unwatch_source(la_source_t *source);

void watch_source(la_source_t *source, int whence);

la_source_t *find_source_by_location(const char *location);

la_source_t *create_source(const char *name, la_sourcetype_t type, const char *location);

/* watch.c */

void init_watching(void);

void watch_forever(void);

#if HAVE_INOTIFY
/* inotify.c */

void unwatch_source_inotify(la_source_t *source);

void watch_forever_inotify(void);

void watch_source_inotify(la_source_t *source);

void init_watching_inotify(void);
#endif /* HAVE_INOTIFY */

/* log.c */

void handle_new_content(la_source_t *source);


#endif /* __logactiond_h */

/* vim: set autowrite expandtab: */
