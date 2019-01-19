#ifndef __logactiond_h
#define __logactiond_h


#include <config.h>

#include <sys/inotify.h>
#include <sys/select.h>
#include <regex.h>
#include <stdbool.h>
#include <time.h>

#include <libconfig.h>

#include "nodelist.h"



//#define NDEBUG

#define CONF_DIR "/etc/logactiond"
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

#define LA_RULES_LABEL "rules"
#define LA_RULE_SOURCE_LABEL "source"
#define LA_RULE_TYPE_LABEL "type"
#define LA_RULE_TYPE_FILE_OPTION "file"
#define LA_RULE_TYPE_SYSTEMD_OPTION "systemd"
#define LA_RULE_ACTION_LABEL "action"
#define LA_RULE_PATTERN_LABEL "pattern"

#define LA_PATTERNS_LABEL "patterns"

#define LA_LOCATION "location"

//#define LA_TOKEN "<HOST>"
//#define LA_TOKEN_LEN 6
//#define LA_TOKEN_REPL "([.:[:xdigit:]]+)"
#define LA_TOKEN_REPL "(.+)"
#define LA_TOKEN_REPL_LEN 4

// maximum number of tokens that can be matched

#define MAX_NMATCH 20


/* Types */

typedef struct la_source_s la_source_t;
typedef struct la_rule_s la_rule_t;
typedef struct la_command_s la_command_t;

// TODO: add default type
typedef enum la_sourcetype_s { LA_RULE_TYPE_FILE, LA_RULE_TYPE_SYSTEMD } la_sourcetype_t;

typedef struct la_address_s
{
	kw_node_t node;
	const char *ip;
} la_address_t;

/*
 * bla
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
	char *name;
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
	kw_list_t *actions;
	unsigned int threshold;
	unsigned int period;
	unsigned int duration;
	kw_list_t *trigger_list;
	kw_list_t *properties;
} la_rule_t;

typedef struct la_trigger_s
{
	kw_node_t node;
	char *name;
	la_command_t *command;
	unsigned int n_triggers;/* how man times triggered during period */
	time_t start_time;	/* time of first trigger during period */
	char *host;		/* IP address */
} la_trigger_t;

typedef struct la_command_s
{
	kw_node_t node;
	const char *string;	/* string with tokens */
	kw_list_t *properties;	/* detected tokens */
	unsigned int n_properties;/* number of detected tokens */
	la_rule_t *rule;	/* related rule */
	la_pattern_t *pattern;	/* related pattern*/
	char *host;		/* IP address */
	la_command_t *end_command;/* end_command - if any */
	int duration;		/* duration how long command shall stay active,
				   -1 if none */

	/* only relevant for end_commands */
	time_t end_time;	/* specific time for enqueued end_commands */

	/* only relevant in trigger_list */
	unsigned int n_triggers;/* how man times triggered during period */
	time_t start_time;	/* time of first trigger during period */
	time_t fire_time;	/* time when command was fired */

} la_command_t;

typedef struct la_action_s
{
	kw_node_t node;
	const char *name;
	la_rule_t *rule;
	la_command_t *initialize;
	la_command_t *begin;
} la_action_t;

typedef struct la_source_s
{
	kw_node_t node;
	const char *name;
	la_sourcetype_t type;
	const char *location;
	const char *parent_dir;
	kw_list_t *rules;
	FILE *file;
#if HAVE_INOTIFY
        int wd;
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

/* Functions */

/* misc.c */

void xfree (void *ptr);

void la_debug(char *fmt, ...);

void la_log_errno(int priority, char *fmt, ...);

void la_log(int priority, char *fmt, ...);

void die_syntax(void);

void die_semantic(char *fmt, ...);

void die_hard(char *fmt, ...);

void die_err(char *fmt, ...);

void *xmalloc(size_t n);

char *xstrdup(const char *s);

char *xstrndup(const char *s, size_t n);

/* libconfigadapter.c */

const char* config_get_string_or_null(
		const config_setting_t *setting, const char *name);

int config_get_unsigned_int_or_negative(const config_setting_t *setting,
		const char *name);

const char* config_get_string_or_die(
		const config_setting_t *setting, const char *name);

const config_setting_t *config_setting_lookup_or_die(const config_setting_t *setting,
		const char *path);

const config_setting_t *get_action(const char *action_name);

const config_setting_t *get_pattern(const char *pattern_name);

const char *get_source_name(const config_setting_t *rule);

const char *get_source_location(const config_setting_t *rule);

la_sourcetype_t get_source_type(const config_setting_t *rule);

/* configfile.c */

int *load_la_config(char *filename);

void unload_la_config(void);

/* addresses.c */

bool address_on_ignore_list(const char *ip);

la_address_t *create_address(const char *ip);

/* endqueue.c */

void empty_end_queue(void);

void enqueue_end_command(la_command_t *end_command, int duration);

void init_end_queue(void);

/* commands.c */

void trigger_command(la_command_t *command);

la_command_t * dup_command(la_command_t *command);

la_command_t *create_command(const char *string, int duration);

/* actions.c */

la_action_t *create_action(const char *name, la_rule_t *rule,
		const char *initialize, const char *shutdown,
		const char *begin, const char *end);


/* properties.c */

const char *get_value_from_property_list(kw_list_t *property_list,
		la_property_t *property);

la_property_t *create_property_from_config(const char *name, const char *value);

la_property_t *create_property_from_action_token(const char *name, size_t length,
		unsigned int pos);

la_property_t *create_property_from_token(const char *name, size_t length, unsigned
		int pos, unsigned int subexpression);

/* patterns.c */

la_pattern_t *create_pattern(const char *string_from_configfile, la_rule_t *rule);

/* rules. c */

void handle_log_line_for_rule(la_rule_t *rule, char *line);

la_rule_t * create_rule(char *name, la_source_t *source, int threshold,
		int period, int duration);

/* sources.c */

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
