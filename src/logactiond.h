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

#include <regex.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>

#include <libconfig.h>
#ifndef NOCRYPTO
#include <sodium.h>
#endif /* NOCRYPTO */

#include "nodelist.h"



//#define NDEBUG

#define SYSLOG_IDENT PACKAGE

#if !defined(CONF_DIR)
#define CONF_DIR "/etc/logactiond"
#endif /* !defined(CONF_DIR) */

#define CONFIG_FILE "logactiond.cfg"

#if !defined(STATE_DIR)
#define STATE_DIR "/var/lib/logactiond"
#endif /* !defined(STATE_DIR) */

#define STATE_FILE "logactiond.state"

#define DEFAULT_THRESHOLD 3
#define DEFAULT_PERIOD 600
#define DEFAULT_DURATION 600

#define DEFAULT_META_ENABLED false
#define DEFAULT_META_PERIOD 3600
#define DEFAULT_META_FACTOR 2
#define DEFAULT_META_MAX 86400

#define DEFAULT_DNSBL_ENABLED false

#define DEFAULT_PORT 16473
#define DEFAULT_PORT_STR "16473"

#if HAVE_RUN
#define RUNDIR "/run"
#else
#define RUNDIR "/var/run"
#endif

#define PIDFILE RUNDIR "/logactiond.pid"
#define HOSTSFILE RUNDIR "/logactiond.hosts"
#define RULESFILE RUNDIR "/logactiond.rules"
#define DIAGFILE RUNDIR "/logactiond.diagnostics"
#define FIFOFILE RUNDIR "/logactiond.fifo"


#define LA_DEFAULTS_LABEL "defaults"

#define LA_PROPERTIES_LABEL "properties"

#define LA_THRESHOLD_LABEL "threshold"
#define LA_PERIOD_LABEL "period"
#define LA_DURATION_LABEL "duration"

#define LA_IGNORE_LABEL "ignore"

#define LA_META_ENABLED_LABEL "meta_enabled"
#define LA_META_PERIOD_LABEL "meta_period"
#define LA_META_FACTOR_LABEL "meta_factor"
#define LA_META_MAX_LABEL "meta_max"

#define LA_DNSBL_ENABLED_LABEL "dnsbl_enabled"

#define LA_SERVICE_LABEL "service"

#define LA_ACTIONS_LABEL "actions"
#define LA_ACTION_INITIALIZE_LABEL "initialize"
#define LA_ACTION_SHUTDOWN_LABEL "shutdown"
#define LA_ACTION_BEGIN_LABEL "begin"
#define LA_ACTION_END_LABEL "end"
#define LA_ACTION_NEED_HOST_LABEL "need_host"
#define LA_ACTION_NEED_HOST_NO_LABEL "no"
#define LA_ACTION_NEED_HOST_ANY_LABEL "any"
#define LA_ACTION_NEED_HOST_IP4_LABEL "4"
#define LA_ACTION_NEED_HOST_IP6_LABEL "6"

#define LA_SOURCES_LABEL "sources"

#define LA_LOCAL_LABEL "local"
#define LA_ENABLED_LABEL "enabled"

#define LA_BLACKLISTS_LABEL "blacklists"

#define LA_RULES_LABEL "rules"
#define LA_RULE_SOURCE_LABEL "source"
#define LA_RULE_ACTION_LABEL "action"
#define LA_RULE_PATTERNS_LABEL "pattern"
#define LA_RULE_SYSTEMD_UNIT_LABEL "systemd-unit"

#define LA_SOURCE_LOCATION "location"
#define LA_SOURCE_PREFIX "prefix"

#define LA_REMOTE_LABEL "remote"
#define LA_REMOTE_RECEIVE_FROM_LABEL "receive_from"
#define LA_REMOTE_SEND_TO_LABEL "send_to"
#define LA_REMOTE_SECRET_LABEL "secret"
#define LA_REMOTE_BIND_LABEL "bind"
#define LA_REMOTE_PORT_LABEL "port"

#define LA_TOKEN_REPL "(.+)"
#define LA_TOKEN_REPL_LEN 4

#define LA_HOST_TOKEN "host"
#define LA_HOST_TOKEN_REPL "([.:[:xdigit:]]+)"
#define LA_HOST_TOKEN_REPL_LEN 17
#define LA_SERVICE_TOKEN "service"

#define LA_RULENAME_TOKEN "rulename"
#define LA_SOURCENAME_TOKEN "sourcename"
#define LA_PATTERNNAME_TOKEN "patternname"
#define LA_IPVERSION_TOKEN "ipversion"

// maximum number of tokens that can be matched

#define MAX_NMATCH 20

// buffer size for reading log lines
#define DEFAULT_LINEBUFFER_SIZE 8192

// verbose debugging loglevel
#define LOG_VDEBUG (LOG_DEBUG+1)

/* List macros */

#define ITERATE_ADDRESSES(ADDRESSES) (la_address_t *) &(ADDRESSES)->head
#define NEXT_ADDRESS(ADDRESS) (la_address_t *) (ADDRESS->node.succ->succ ? ADDRESS->node.succ : NULL)
#define HAS_NEXT_ADDRESS(ADDRESS) ADDRESS->node.succ
#define REM_ADDRESSES_HEAD(ADDRESSES) (la_address_t *) rem_head(ADDRESSES)

#define ITERATE_COMMANDS(COMMANDS) (la_command_t *) &(COMMANDS)->head
#define NEXT_COMMAND(COMMAND) (la_command_t *) (COMMAND->node.succ->succ ? COMMAND->node.succ : NULL)
#define HAS_NEXT_COMMAND(COMMAND) COMMAND->node.succ
#define REM_COMMANDS_HEAD(COMMANDS) (la_command_t *) rem_head(COMMANDS)

#define ITERATE_PATTERNS(PATTERNS) (la_pattern_t *) &(PATTERNS)->head
#define NEXT_PATTERN(PATTERN) (la_pattern_t *) (PATTERN->node.succ->succ ? PATTERN->node.succ : NULL)
#define HAS_NEXT_PATTERN(PATTERN) PATTERN->node.succ
#define REM_PATTERNS_HEAD(PATTERNS) (la_pattern_t *) rem_head(PATTERNS)

#define ITERATE_PROPERTIES(PROPERTIES) (la_property_t *) &(PROPERTIES)->head
#define NEXT_PROPERTY(PROPERTY) (la_property_t *) (PROPERTY->node.succ->succ ? PROPERTY->node.succ : NULL)
#define HAS_NEXT_PROPERTY(PROPERTY) PROPERTY->node.succ
#define REM_PROPERTIES_HEAD(PROPERTIES) (la_property_t *) rem_head(PROPERTIES)

#define ITERATE_RULES(RULES) (la_rule_t *) &(RULES)->head
#define NEXT_RULE(RULE) (la_rule_t *) (RULE->node.succ->succ ? RULE->node.succ : NULL)
#define HAS_NEXT_RULE(RULE) RULE->node.succ
#define REM_RULES_HEAD(RULES) (la_rule_t *) rem_head(RULES)

#define ITERATE_SOURCES(SOURCES) (la_source_t *) &(SOURCES)->head
#define NEXT_SOURCE(SOURCE) (la_source_t *) (SOURCE->node.succ->succ ? SOURCE->node.succ : NULL)
#define HAS_NEXT_SOURCE(SOURCE) SOURCE->node.succ
#define REM_SOURCES_HEAD(SOURCES) (la_source_t *) rem_head(SOURCES)

/* assertions */

#ifdef NDEBUG
#define assert_command(COMMAND) (void)(0)
#define assert_rule(RULE) (void)(0)
#define assert_source(SOURCE) (void)(0)
#define assert_pattern(PATTERN) (void)(0)
#define assert_address(ADDRESS) (void)(0)
#define assert_property(PROPERTY) (void)(0)
#else /* NDEBUG */
#define assert_command(COMMAND) assert_command_ffl(COMMAND, __func__, __FILE__, __LINE__)
#define assert_rule(RULE) assert_rule_ffl(RULE, __func__, __FILE__, __LINE__)
#define assert_source(SOURCE) assert_source_ffl(SOURCE, __func__, __FILE__, __LINE__)
#define assert_pattern(PATTERN) assert_pattern_ffl(PATTERN, __func__, __FILE__, __LINE__)
#define assert_address(ADDRESS) assert_address_ffl(ADDRESS, __func__, __FILE__, __LINE__)
#define assert_property(PROPERTY) assert_property_ffl(PROPERTY, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

/* Remote protocol */

#define PROTOCOL_VERSION '0'

/* Length of unencrypted message*/
#define MSG_LEN 175
/* Length of encrypted message (i.e. incl. MAC */
#define ENC_MSG_LEN MSG_LEN + crypto_secretbox_MACBYTES
/* Length of whole message that will be send, i.e.
 * - nonce
 * - MAC
 * - the encrypted message
 */
#define TOTAL_MSG_LEN ENC_MSG_LEN + crypto_secretbox_NONCEBYTES + crypto_pwhash_SALTBYTES

#define MSG_IDX 0
#define SALT_IDX ENC_MSG_LEN
#define NONCE_IDX ENC_MSG_LEN+crypto_pwhash_SALTBYTES

typedef enum la_commandtype_s { LA_COMMANDTYPE_BEGIN, LA_COMMANDTYPE_END } la_commandtype_t;

typedef enum la_need_host_s { LA_NEED_HOST_NO, LA_NEED_HOST_ANY,
        LA_NEED_HOST_IP4, LA_NEED_HOST_IP6 } la_need_host_t;

typedef enum la_runtype_s { LA_DAEMON_BACKGROUND, LA_DAEMON_FOREGROUND,
        LA_UTIL_FOREGROUND } la_runtype_t;

/*
 * bla
 */

typedef struct la_address_s
{
        kw_node_t node;
        struct sockaddr_storage sa;
        int prefix;
        char *text;

        /* only used for hosts that we receive messages from */
#ifndef NOCRYPTO
        unsigned char key[crypto_secretbox_KEYBYTES];
        unsigned char salt[crypto_pwhash_SALTBYTES];
#endif
} la_address_t;

/*
 * la_property_s
 *
 * Note: both name and value must be assigned strdup()ed strings
 */

typedef struct la_property_s
{
        kw_node_t node;
        /* name of the property (for matched tokens: without the '%'s) */
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
         * BTW: strings will be strdup()ed - take care to free again */
        char *value;

        /* Only for tokens matching a log line. Specifies the regex that the
         * %token% should be replaced with.
         */
        char *replacement;

        /* The following  members will only be used when properties are
         * obtained from log lines matching tokens or in action strings.
         */

        /* Position in original string. Points to innitial '%'!.
         * Only for use in convert_regex() */
        unsigned int pos;
        /* Length of token including the two '%'. Saves us a few strlen() calls in
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
        unsigned int num; // position of the pattern in the config file
        struct la_rule_s *rule;
        char *string; /* already converted regex, doesn't contain tokens anymore */
        regex_t *regex; /* compiled regex */
        kw_list_t *properties; /* list of la_property_t */
        unsigned long int detection_count;
        unsigned long int invocation_count;
} la_pattern_t;

typedef struct la_rule_s
{
        kw_node_t node;
        char *name;
        unsigned int id;
        struct la_source_s *source;
        char *service;
        kw_list_t *patterns;
        kw_list_t *begin_commands;
        unsigned int threshold;
        unsigned int period;
        unsigned int duration;
        bool meta_enabled;
        unsigned int meta_period;
        int meta_factor;
        unsigned int meta_max;
        char *systemd_unit;
        kw_list_t *trigger_list;
        kw_list_t *properties;
        unsigned long int detection_count;
        unsigned long int invocation_count;
        unsigned long int queue_count;
        bool dnsbl_enabled;
        kw_list_t *blacklists;
} la_rule_t;

typedef struct la_command_s
{
        kw_node_t node;
        char *name;       /* name of action */
        unsigned int id;        /* unique id */
        bool is_template;       /* true for templates, false for derived commands */
        char *begin_string;        /* string with tokens */
        kw_list_t *begin_properties;        /* detected tokens */
        unsigned int n_begin_properties;/* number of detected tokens */
        char *end_string;        /* string with tokens */
        kw_list_t *end_properties;        /* detected tokens */
        unsigned int n_end_properties;/* number of detected tokens */
        struct la_rule_s *rule;        /* related rule */
        la_pattern_t *pattern;        /* related pattern*/
        kw_list_t *pattern_properties; /* properties from matched pattern */
        la_address_t *address;     /* IP address */
        la_need_host_t need_host;    /* Command requires host */
        int duration;                /* duration how long command shall stay active,
                                   -1 if none */
        int factor;
        bool manual;            /* True if command has been manually submitted */
        bool blacklist;         /* True if command has been triggered via blacklist */

        /* only relevant for end_commands */
        time_t end_time;        /* specific time for enqueued end_commands */
        char *rule_name;

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
        char *name;
        /* Filename (or equivalent) - strdup()d */
        char *location;
        /* Parent dir of log file - currently only used for inotify */
        char *parent_dir;
        /* Rules assigned to log file */
        kw_list_t *rules;
        /* Prefix to prepend before rule patterns */
        char *prefix;
        /* File handle for log file */
        FILE *file;
        /* stat() result for file */
        struct stat stats;
        /* File is currently "watchable" - only used by polling backend */
        bool active;

        /* Next two are only used in inotify.c */

        /* Watch descriptor for log file itself */
        int wd;
        /* Watch descriptor for parent directory */
        int parent_wd;

        /* Next one is only used in systemd.c */

        /* systemd_units we're interested in */
        kw_list_t *systemd_units;
} la_source_t;

typedef struct la_config_s
{
        config_t config_file;
        kw_list_t *sources;
        struct la_source_s *systemd_source;
        int default_threshold;
        int default_period;
        int default_duration;
        int default_meta_enabled; /* should be bool but well... */
        int default_meta_period;
        int default_meta_factor;
        int default_meta_max;
        kw_list_t *default_properties;
        kw_list_t *ignore_addresses;
        int remote_enabled;
        kw_list_t *remote_receive_from;
        kw_list_t *remote_send_to;
        char *remote_secret;
        char *remote_bind;
        int remote_port;
} la_config_t;

/* Global variables */

extern la_config_t *la_config;

extern pthread_t file_watch_thread;
extern pthread_t systemd_watch_thread;
extern pthread_t end_queue_thread;
extern pthread_t monitoring_thread;
extern pthread_t fifo_thread;
extern pthread_t remote_thread;

extern pthread_mutex_t config_mutex;
extern pthread_mutex_t end_queue_mutex;

extern kw_list_t *end_queue;

extern unsigned int log_level;
extern bool log_verbose;

extern unsigned int id_counter;

extern la_runtype_t run_type;

extern unsigned int status_monitoring;

extern bool shutdown_ongoing;

extern int exit_status;

/* Functions */

/* logactiond.c */

void trigger_shutdown(int status, int saved_errno);

void trigger_reload(void);

/* misc.c */

void remove_pidfile(void);

void create_pidfile(void);

void xpthread_create(pthread_t *thread, const pthread_attr_t *attr,
                void *(*start_routine)(void *), void *arg, char *name);

void xpthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

void xpthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                const struct timespec *abstime);

void xpthread_cond_signal(pthread_cond_t *cond);

void xpthread_mutex_lock(pthread_mutex_t *mutex);

void xpthread_mutex_unlock(pthread_mutex_t *mutex);

void xpthread_join(pthread_t thread, void **retval);

time_t xtime(time_t *tloc);

void xfree (void *ptr);

void log_message(unsigned int priority, char *fmt, va_list gp, char *add);

void la_debug(char *fmt, ...);

void la_vdebug(char *fmt, ...);

void la_log_errno(unsigned int priority, char *fmt, ...);

void la_log_verbose(unsigned int priority, char *fmt, ...);

void la_log(unsigned int priority, char *fmt, ...);

void die_hard(char *fmt, ...);

void die_err(char *fmt, ...);

void *xrealloc(void *ptr, size_t n);

void *xmalloc0(size_t n);

void *xmalloc(size_t n);

char *xstrdup(const char *s);

char *xstrndup(const char *s, size_t n);

size_t xstrlen(const char *s);

char *concat(const char *s1, const char *s2);

void realloc_buffer(char **dst, char **dst_ptr, size_t *dst_len, size_t on_top);

kw_list_t *xcreate_list(void);

char *xgetpass (const char *prompt);

/* crypto.c */

bool generate_send_key_and_salt(unsigned char *key, char *password,
                unsigned char *salt);

bool decrypt_message(char *buffer, char *password, la_address_t *from_addr);

bool encrypt_message(char *buffer, char *password);

void pad(char *buffer, size_t msg_len);

/* messages.c */

#ifndef CLIENTONLY
int parse_add_entry_message(char *message, la_address_t **address,
                la_rule_t **rule, time_t *end_time, int *factor);

void parse_message_trigger_command(char *buf, char *from);
#endif /* CLIENTONLY */

char *create_add_message(char *ip, char *rule, char *end_time, char *factor);

int print_add_message(FILE *stream, la_command_t *command);

char *create_del_message(char *ip);

char *create_empty_queue_message(void);

char *create_flush_message(void);

char *create_reload_message(void);

char *create_shutdown_message(void);

char *create_save_message(void);

char *create_restore_message(void);

/* configfile.c */

void load_la_config(char *filename);

void unload_la_config(void);

/* addresses.c */

void assert_address_ffl(la_address_t *address, const char *func, char *file,
                unsigned int line);

const char *get_ip_version(la_address_t *address);

int adrcmp(la_address_t *a1, la_address_t *a2);

la_address_t *address_on_list(la_address_t *address, kw_list_t *list);

la_address_t *address_on_list_sa(struct sockaddr *sa, socklen_t salen, kw_list_t *list);

la_address_t *address_on_list_str(char *host, kw_list_t *list);

la_address_t *create_address_sa(struct sockaddr *sa, socklen_t salen);

la_address_t *create_address_port(const char *ip, in_port_t port);

la_address_t *create_address(const char *ip);

la_address_t *dup_address(la_address_t *address);

void free_address(la_address_t *address);

void empty_address_list(kw_list_t *list);

void free_address_list(kw_list_t *list);

/* endqueue.c */

void update_queue_count_numbers(void);

la_command_t *find_end_command(la_address_t *address);

int remove_and_trigger(la_address_t *address);

void empty_end_queue();

void save_queue_state(void);

void enqueue_end_command(la_command_t *end_command);

void init_end_queue(void);

void start_end_queue_thread(void);

/* commands.c */

void exec_command(la_command_t *command, la_commandtype_t type);

unsigned int meta_list_length(void);

void free_meta_list(void);

void assert_command_ffl(la_command_t *command, const char *func, char *file, unsigned int line);

void trigger_manual_command(la_address_t *address, la_command_t *template,
                time_t end_time, int factor, char *from);

void trigger_command(la_command_t *command);

void trigger_command_from_blacklist(la_command_t *command);

void trigger_end_command(la_command_t *command, bool suppress_logging);

la_command_t * create_command_from_template(la_command_t *template,
                la_pattern_t *pattern, la_address_t *address);

la_command_t * create_manual_command_from_template(la_command_t *template,
                la_address_t *address);

la_command_t *create_template(const char *name, la_rule_t *rule,
                const char *begin_string, const char *end_string,
                unsigned int duration, la_need_host_t need_host);

void free_command(la_command_t *command);

void free_command_list(kw_list_t *list);

/* properties.c */

void assert_property_ffl(la_property_t *property, const char *func, char *file,
                unsigned int line);

size_t token_length(const char *string);

const char *get_host_property_value(kw_list_t *property_list);

la_property_t *get_property_from_property_list(kw_list_t *property_list,
                const char *name);

const char *get_value_from_property_list(kw_list_t *property_list,
                const char *name);

la_property_t *scan_single_token(const char *string, unsigned int pos,
                la_rule_t *rule);

la_property_t *create_property_from_config(const char *name, const char *value);

kw_list_t *dup_property_list(kw_list_t *list);

void free_property(la_property_t *property);

void empty_property_list(kw_list_t *list);

void free_property_list(kw_list_t *list);

/* patterns.c */

void assert_pattern_ffl(la_pattern_t *pattern, const char *func, char *file, unsigned int line);

la_pattern_t *create_pattern(const char *string_from_configfile,
                unsigned int num, la_rule_t *rule);

void free_pattern(la_pattern_t *pattern);

void free_pattern_list(kw_list_t *list);

/* rules.c */

void assert_rule_ffl(la_rule_t *rule, const char *func, char *file, unsigned int line);

void handle_log_line_for_rule(la_rule_t *rule, const char *line);

void trigger_manual_commands_for_rule(la_address_t *address, la_rule_t *rule,
                time_t end_time, int factor, char *from);

la_rule_t *create_rule(char *name, la_source_t *source, int threshold,
                int period, int duration, int meta_enabled, int meta_period,
                int meta_factor, int meta_max, int dnsbl_enabled, const char
                *service, const char *systemd_unit);

void free_rule(la_rule_t *rule);

void free_rule_list(kw_list_t *list);

la_rule_t *find_rule(char *rule_name);

/* sources.c */

void assert_source_ffl(la_source_t *source, const char *func, char *file, unsigned int line);

void handle_log_line(la_source_t *source, const char *line, const char *systemd_unit);

bool handle_new_content(la_source_t *source);

la_source_t *create_source(const char *name, const char *location,
                const char *prefix);

void free_source(la_source_t *source);

void empty_source_list(kw_list_t *list);

void free_source_list(kw_list_t *list);

la_source_t *find_source_by_location(const char *location);


#if HAVE_LIBSYSTEMD
/* systemd.c */

void init_watching_systemd(void);

void start_watching_systemd_thread(void);

void add_systemd_unit(const char *systemd_unit);

#endif /* HAVE_LIBSYSTEMD */

#if HAVE_INOTIFY
/* inotify.c */

void unwatch_source_inotify(la_source_t *source);

void watch_source_inotify(la_source_t *source);

void init_watching_inotify(void);

void start_watching_inotify_thread(void);

#endif /* HAVE_INOTIFY */

/* polling.c */

void start_watching_polling_thread(void);

/* status.c */

void start_monitoring_thread(void);

void dump_queue_status(kw_list_t *queue);

/* watch.c */

void watch_source(la_source_t *source, int whence);

void unwatch_source(la_source_t *source);

void init_watching(void);

void start_watching_threads(void);

void shutdown_watching(void);

/* fifo.c */

void start_fifo_thread(void);

/* remote.c */

void send_add_entry_message(la_command_t *command);

void start_remote_thread(void);

/* dnsbl.c */

bool host_on_dnsbl(la_address_t *address, char *dnsbl_domainname);

#endif /* __logactiond_h */

/* vim: set autowrite expandtab: */
