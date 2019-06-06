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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <err.h>
#include <syslog.h>
#include <assert.h>

#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/stat.h>
#include <pthread.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

la_config_t *la_config = NULL;

pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Return string for path relative to setting. Return NULL if element does not
 * exist.
 */

const char*
config_get_string_or_null(const config_setting_t *setting, const char *name)
{
        const char* result;
        if (!config_setting_lookup_string(setting, name, &result))
                result = NULL;

        return result;
}

/*
 * Return unsigned int for path relative to setting. Return -1 if element does
 * not exist.
 */

int
config_get_unsigned_int_or_negative(const config_setting_t *setting,
                const char *name)
{
        int result;
        if (!config_setting_lookup_int(setting, name, &result))
                return -1;

        return result;
}

/*
 * Return string for path relative to setting. Die if element does not exist
 */

const char*
config_get_string_or_die(const config_setting_t *setting, const char *name)
{
        const char* result = config_get_string_or_null(setting, name);

        if (!result)
                die_semantic("Config element %s missing!", name);

        return result;
}

/*
 * Return config_setting_t for path relative to setting. Die if element does
 * not exist
 */

const config_setting_t *
config_setting_lookup_or_die(const config_setting_t *setting,
                const char *path)
{
        const config_setting_t *result;
        /* TODO: not sure why config_setting_t * (without const) is required
         * here but nowhere else */
        result = config_setting_lookup((config_setting_t *) setting, path);
        if (!result)
                die_semantic("Config element %s missing!", path);

        return result;
}

static const config_setting_t *
get_rule(const char *rule_name)
{
        assert(rule_name);

        return config_setting_lookup_or_die(config_lookup(
                                &la_config->config_file,
                                LA_RULES_LABEL), rule_name);
}

/*
 * Returns a config_setting_t to an action within the main actions section -
 * specified by the action_name.
 *
 * Returns NULL in case no pattern with that name exists
 */

const config_setting_t *
get_action(const char *action_name)
{
        assert(action_name);

        return config_setting_lookup_or_die(config_lookup(
                                &la_config->config_file,
                                LA_ACTIONS_LABEL), action_name);
}


/*
 * Return config_setting_t for given source name.
 *
 * Return NULL in case of an error -e.g. when source == NULL.
 *
 *
 * TODO: not needed anymore?
 */

static config_setting_t *
get_source(const char *source)
{
        config_setting_t *sources_section;
        config_setting_t *result;

        if (!source)
                return NULL;

        sources_section = config_lookup(&la_config->config_file, LA_SOURCES_LABEL);
        if (!sources_section)
                die_semantic(LA_SOURCES_LABEL " section missing!");

        result = config_setting_lookup(sources_section, source);

        return  result;
}

/*
 * Return config_setting_t for given rule. Look first in uc_rule, then rule.
 * Die if not found in either definition.
 */

static config_setting_t *
get_source_uc_rule_or_rule(const config_setting_t *rule,
                const config_setting_t *uc_rule)
{
        config_setting_t *result;

        result = get_source(config_get_string_or_null(uc_rule,
                                LA_RULE_SOURCE_LABEL));

        if (!result)
                result = get_source(config_get_string_or_null(rule,
                                        LA_RULE_SOURCE_LABEL));

        if (!result)
                die_semantic("Source not found for rule %s!",
                                config_setting_name(rule));

        return result;
}

/*
 * Returns name of source - i.e. label reference by "source" item in a rule
 * section.
 */

const char *
get_source_name(const config_setting_t *rule)
{
        assert(rule);

        return config_get_string_or_die(rule, LA_RULE_SOURCE_LABEL);
}

/*
 * Return the common prefix for the source corresponding to the given rule,
 * NULL if none specified in config file.
 */

const char *
get_source_prefix(const config_setting_t *rule, const config_setting_t *uc_rule)
{
        assert(rule), assert(uc_rule);

        const char *result;
        config_setting_t *source_def = get_source_uc_rule_or_rule(rule, uc_rule);

        if (!config_setting_lookup_string(source_def, LA_SOURCE_PREFIX, &result))
                result = NULL;

        return result;
}

/*
 * Return source location to corresponding rule. Look first in user
 * configuration section, then in rule section.
 */

const char *
get_source_location(const config_setting_t *rule, const config_setting_t *uc_rule)
{
        assert(rule); assert(uc_rule);

        config_setting_t *source_def;
        const char *result;

        source_def = get_source_uc_rule_or_rule(rule, uc_rule);

        if (!config_setting_lookup_string(source_def, LA_SOURCE_LOCATION, &result))
                die_semantic("Source location missing!");

        return result;
}

static la_sourcetype_t
get_source_type(const config_setting_t *rule)
{
        config_setting_t *source_def;
        const char *type;

        source_def = get_source(config_get_string_or_die(rule, LA_RULE_SOURCE_LABEL));
        if (!source_def)
                die_semantic("Source not found!");

        type = config_get_string_or_die(source_def, LA_SOURCE_TYPE_LABEL);

        if (!strcmp(type, LA_SOURCE_TYPE_FILE_OPTION))
                return LA_SOURCE_TYPE_FILE;
        else if (!strcmp(type, LA_SOURCE_TYPE_SYSTEMD_OPTION))
                return LA_SOURCE_TYPE_SYSTEMD;
        else
                die_semantic("Wrong source type \"%s\" specified!", type);

        return 0; // avoid warning
}

/*
 * Add command for each action's begin command to the begin_commands of
 * the corresponding rule.
 */

static void
compile_actions(la_rule_t *rule, const config_setting_t *action_def)
{
        assert_rule(rule); assert(action_def);

        la_debug("compile_actions(%s)", rule->name);

        const char *name = config_setting_name(action_def);
        const char *initialize = config_get_string_or_null(action_def,
                        LA_ACTION_INITIALIZE_LABEL);
        const char *shutdown = config_get_string_or_null(action_def,
                        LA_ACTION_SHUTDOWN_LABEL);
        const char *begin = config_get_string_or_die(action_def,
                        LA_ACTION_BEGIN_LABEL);
        const char *end = config_get_string_or_null(action_def,
                        LA_ACTION_END_LABEL);

        const char *tmp = config_get_string_or_null(action_def,
                        LA_ACTION_NEED_HOST_LABEL);
        la_need_host_t need_host;

        if (!tmp)
                need_host = LA_NEED_HOST_NO;
        else if (!strcasecmp(tmp, LA_ACTION_NEED_HOST_NO_LABEL))
                need_host = LA_NEED_HOST_NO;
        else if (!strcasecmp(tmp, LA_ACTION_NEED_HOST_ANY_LABEL))
                need_host = LA_NEED_HOST_ANY;
        else if (!strcasecmp(tmp, LA_ACTION_NEED_HOST_IP4_LABEL))
                need_host = LA_NEED_HOST_IP4;
        else if (!strcasecmp(tmp, LA_ACTION_NEED_HOST_IP6_LABEL))
                need_host = LA_NEED_HOST_IP6;
        else
                die_semantic("Invalid value \"%s\" for need_host "
                                "parameter!", tmp);

        if (initialize)
                trigger_command(create_template(name, rule, initialize,
                                        shutdown, INT_MAX, false));

        if (begin)
                add_tail(rule->begin_commands, (kw_node_t *)
                                create_template(name, rule, begin, end,
                                        rule->duration, need_host));
        else
                die_semantic("Begin action always required!");

        assert_list(rule->begin_commands);
}

static void
compile_list_of_actions(la_rule_t *rule,
                const config_setting_t *action_def)
{
        assert_rule(rule); assert(action_def);

        la_debug("compile_list_of_actions(%s)", rule->name);

        int n_items = config_setting_length(action_def);

        for (unsigned int i=0; i<n_items; i++)
        {
                config_setting_t *list_item =
                        config_setting_get_elem(action_def, i);
                compile_actions(rule, get_action(config_setting_get_string(
                                                list_item)));
        }
}

/*
 * Return a list of all actions (i.e. struct la_action_s) assigned to a rule
 */

static void
load_actions(la_rule_t *rule, const config_setting_t *uc_rule_def)
{
        assert_rule(rule); assert(uc_rule_def);

        la_debug("load_actions(%s)", rule->name);
        const config_setting_t *action_reference;

        /* again unclear why this cast is necessary */
        action_reference = config_setting_lookup((config_setting_t *)
                        uc_rule_def, LA_RULE_ACTION_LABEL);
        if (!action_reference)
        {
                config_setting_t *defaults_section =
                        config_lookup(&la_config->config_file, LA_DEFAULTS_LABEL);
                if (!defaults_section)
                        die_semantic("No action specified for %s!",
                                        config_setting_name(rule));
                action_reference = config_setting_lookup(defaults_section,
                                LA_RULE_ACTION_LABEL);
                if (!action_reference)
                        die_semantic("No action specified for %s!",
                                        config_setting_name(rule));
        }

        int type = config_setting_type(action_reference);

        if (type == CONFIG_TYPE_STRING)
                compile_actions(rule, get_action(
                                        config_setting_get_string(
                                                action_reference)));
        else if (type == CONFIG_TYPE_LIST)
                compile_list_of_actions(rule, action_reference);
        else
                die_semantic("Element neither string nor list!");
}

static void
load_patterns(la_rule_t *rule, const config_setting_t *rule_def, 
                const config_setting_t *uc_rule_def)
{
        assert_rule(rule); assert(rule_def); assert(uc_rule_def);

        la_debug("load_patterns(%s)", rule->name);

        const config_setting_t *patterns;

        /* again unclear why this cast is necessary */
        patterns = config_setting_lookup((config_setting_t *)
                        uc_rule_def, LA_RULE_PATTERNS_LABEL);
        if (!patterns)
                patterns = config_setting_lookup_or_die(rule_def,
                                LA_RULE_PATTERNS_LABEL);

        int n = config_setting_length(patterns);
        if (n < 0)
                die_semantic("No patterns specified for %s!",
                                config_setting_name(rule_def));

        for (unsigned int i=0; i<n; i++)
        {
                const char *item = config_setting_get_string_elem(patterns, i);

                la_pattern_t *pattern = create_pattern(item, i, rule);

                add_tail(rule->patterns, (kw_node_t *) pattern);
        }
        assert_list(rule->patterns);
}


static kw_list_t *
load_ignore_addresses(const config_setting_t *section)
{
        assert(section);

        la_debug("load_ignore_addresses(%s)", config_setting_name(section));

        kw_list_t *result = xcreate_list();

        config_setting_t *ignore_section =
                config_setting_get_member(section, "ignore");

        if (!ignore_section)
                return result;

        int n = config_setting_length(ignore_section);
        for (unsigned int i=0; i<n; i++)
        {
                config_setting_t *elem =
                        config_setting_get_elem(ignore_section, i);
                const char *ip = config_setting_get_string(elem);
                if (!ip)
                        die_hard("Only strings allowed for ignore addresses!");

                la_address_t *address = create_address(ip);
                if (!address)
                        die_err("Invalid IP address %s!", ip);

                la_vdebug("load_ignore_addresses(%s)=%s",
                                config_setting_name(section), address->text);
                add_tail(result, (kw_node_t *) address);
        }
        assert_list(result);

        return result;
}

/*
 * Add all properties which exist in a properties section the given section to
 * the given properties list. Do not add properties which already exist in the
 * list.
 */

static void
load_properties(kw_list_t *properties, const config_setting_t *section)
{
        assert_list(properties); assert(section);

        la_debug("load_properties(%s)", config_setting_name(section));

        config_setting_t *properties_section =
                config_setting_get_member(section, LA_PROPERTIES_LABEL);

        if (!properties_section)
                return;

        int n = config_setting_length(properties_section);
        for (unsigned int i=0; i<n; i++)
        {
                config_setting_t *elem =
                        config_setting_get_elem(properties_section, i);
                const char *name = config_setting_name(elem);
                if (!name)
                        die_hard("Property without a name?!");
                const char *value = config_setting_get_string(elem);
                if (!value)
                        die_hard("Only strings allowed for properties!");

                /* if property with same name already exists, do nothing */
                if (get_property_from_property_list(properties, name))
                        continue;

                la_property_t *property = create_property_from_config(name, value);

                la_vdebug("load_properties(%s)=%s", config_setting_name(section), name);
                add_tail(properties, (kw_node_t *) property);
        }
        assert_list(properties);
}

/*
 * Returns a rule parameter. Always tries local ("uc_rule") definition first.
 * If that doesn't exist, tries the normal rules ("rule") definition. Returns
 * NULL in case neither exists.
 */

static const char *
get_rule_string(const config_setting_t *rule_def,
                const config_setting_t *uc_rule_def, const char *name)
{
        assert(rule_def); assert(uc_rule_def); assert(name);

        const char *result = config_get_string_or_null(uc_rule_def, name);

        if (!result)
                result = config_get_string_or_null(rule_def, name);

        return result;
}

/*
 * Returns a rule parameter. Always tries local ("uc_rule") definition first.
 * If that doesn't exist, tries the normal rules ("rule") definition. Returns
 * NULL in case neither exists.
 */

static int
get_rule_unsigned_int(const config_setting_t *rule_def,
                const config_setting_t *uc_rule_def, const char *name)
{
        assert(rule_def); assert(uc_rule_def); assert(name);

        int result = config_get_unsigned_int_or_negative(uc_rule_def, name);

        if (result < 0)
                result = config_get_unsigned_int_or_negative(rule_def, name);

        return result;
}

/*
 * Create new source, add it to list of sources, begin watching.
 */

static la_source_t *
create_file_source(const config_setting_t *rule_def,
                const config_setting_t *uc_rule_def)
{
        const char *location = get_source_location(rule_def, uc_rule_def);
        const char *prefix = get_source_prefix(rule_def, uc_rule_def);

        la_source_t *result = create_source(get_source_name(rule_def),
                        get_source_type(rule_def), location, prefix);
        assert_source(result);
        add_tail(la_config->sources, (kw_node_t *) result);

        return result;
}

/*
 * Load a single rule
 *
 * rule_def - section were rule is specified (non-user configuration)
 * uc_rule_def - user configuration where rule is enabled an parameters
 * from rule_def may be overwritten.
 */

static void
load_single_rule(const config_setting_t *rule_def,
                const config_setting_t *uc_rule_def)
{
        assert(rule_def); assert(uc_rule_def);
        la_rule_t *new_rule;
        la_source_t *source;
        la_sourcetype_t type;

        char *name = config_setting_name(rule_def);
        la_debug("load_single_rule(%s)", name);

        source = find_source_by_location(get_source_location(rule_def,
                                uc_rule_def));

        if (!source)
                source = create_file_source(rule_def, uc_rule_def);
        assert_source(source);

        /* get parameters either from rule or uc_rule */
        int threshold = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_THRESHOLD_LABEL);
        int period = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_PERIOD_LABEL);
        int duration = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_DURATION_LABEL);
        const char *service = get_rule_string(rule_def, uc_rule_def,
                        LA_SERVICE_LABEL);

        la_log(LOG_INFO, "Enabling rule \"%s\".", name);
        new_rule = create_rule(name, source, threshold, period, duration, service);
        assert_rule(new_rule);

        /* Properties from uc_rule_def have priority over those from
         * rule_def */
        load_properties(new_rule->properties, uc_rule_def);
        load_properties(new_rule->properties, rule_def);

        /* Patterns from uc_rule_def have priority over those from rule_def */
        load_patterns(new_rule, rule_def, uc_rule_def);

        /* actions are only taken from uc_rule_def (or default settings) */
        load_actions(new_rule, uc_rule_def);
        add_tail(source->rules, (kw_node_t *) new_rule);
}


static void
load_rules(void)
{
        la_debug("load_rules()");

        config_setting_t *local_section = 
                config_lookup(&la_config->config_file, LA_LOCAL_LABEL);

        la_config->sources = xcreate_list();

        int n = config_setting_length(local_section);
        if (n < 0)
                die_semantic("No rules enabled!");

        bool any_enabled = false;
        for (int i=0; i<n; i++)
        {
                config_setting_t *uc_rule = 
                        config_setting_get_elem(local_section, i);

                int enabled;
                if (config_setting_lookup_bool(uc_rule, LA_LOCAL_ENABLED_LABEL,
                                        &enabled) == CONFIG_TRUE && enabled)
                {
                        any_enabled = true;
                        load_single_rule(get_rule(config_setting_name(
                                                        config_setting_get_elem(
                                                                local_section,
                                                                i))), uc_rule);
                }
        }

        if (!any_enabled)
                die_semantic("No rules enabledd!");
}

static void
load_defaults(void)
{
        la_debug("load_defaults()");

        config_setting_t *defaults_section =
                config_lookup(&la_config->config_file, LA_DEFAULTS_LABEL);

        if (defaults_section)
        {
                la_config->default_threshold =
                        config_get_unsigned_int_or_negative(defaults_section,
                                        LA_THRESHOLD_LABEL);
                if (la_config->default_threshold == -1)
                        la_config->default_threshold = DEFAULT_THRESHOLD;
                la_config->default_period =
                        config_get_unsigned_int_or_negative(defaults_section,
                                        LA_PERIOD_LABEL);
                if (la_config->default_period == -1)
                        la_config->default_period = DEFAULT_PERIOD;
                la_config->default_duration =
                        config_get_unsigned_int_or_negative(defaults_section,
                                        LA_DURATION_LABEL);
                if (la_config->default_duration == -1)
                        la_config->default_duration = DEFAULT_DURATION;

                la_config->default_properties = xcreate_list();
                load_properties(la_config->default_properties, defaults_section);
                la_config->ignore_addresses = load_ignore_addresses(defaults_section);
        }
        else
        {
                la_config->default_threshold = DEFAULT_THRESHOLD;
                la_config->default_period = DEFAULT_PERIOD;
                la_config->default_duration = DEFAULT_DURATION;
                la_config->default_properties = NULL;
                la_config->ignore_addresses = NULL;
        }
}

const char ** include_func(config_t *config, const char *include_dir, const
                char *path, const char **error);

/*
 * Initializes the config_mutex as recursive mutex (thus making it possible to
 * lock it multiple times from within the same thread without blocking it).
 *
 * Commented out, as it's currently not needed but left here in case I'll need
 * it at some later point.
 *
 * TODO: make sure this only gets called once, even when config is reloaded.
 */

/*static void
init_config_mutex(void)
{
        pthread_mutexattr_t config_mutex_attr;

        pthread_mutexattr_init(&config_mutex_attr);
        if (pthread_mutexattr_settype(&config_mutex_attr, PTHREAD_MUTEX_RECURSIVE))
                die_err("Can't set mutex attributes!");
        pthread_mutex_init(&config_mutex, &config_mutex_attr);
}*/

void
load_la_config(char *filename)
{
        if (!filename)
                filename = CONFIG_FILE;

        //init_config_mutex();

        xpthread_mutex_lock(&config_mutex);

        la_log(LOG_INFO, "Loading configuration from \"%s/%s\".", CONF_DIR,
                        filename);

        la_config = xmalloc0(sizeof(la_config_t));

        config_init(&la_config->config_file);

        config_set_include_func(&la_config->config_file, include_func);

        if (!config_read_file(&la_config->config_file, filename))
        {
                const char *config_error_file =
                        config_error_file(&la_config->config_file);
                xpthread_mutex_unlock(&config_mutex);
                if (config_error_file)
                        die_hard("%s:%d - %s!",
                                        config_error_file(&la_config->config_file),
                                        config_error_line(&la_config->config_file),
                                        config_error_text(&la_config->config_file));
                else
                        die_hard("%s!", config_error_text(&la_config->config_file));
        }

        load_defaults();
        load_rules();

        config_destroy(&la_config->config_file);

        xpthread_mutex_unlock(&config_mutex);
}

void
unload_la_config(void)
{
        la_debug("unload_la_config()");

        if (!la_config)
                return;

        xpthread_mutex_lock(&config_mutex);

        free_source_list(la_config->sources);
        free_property_list(la_config->default_properties);
        free_address_list(la_config->ignore_addresses);
        free(la_config);
        la_config = NULL;

        xpthread_mutex_unlock(&config_mutex);
}

/*
 * Copied from example4.c from the libconfig distribution
 */

const char **
include_func(config_t *config, const char *include_dir, const char *path, const char **error)
{
        char *p;
        DIR *dp;
        struct dirent *dir_entry;
        struct stat stat_buf;
        char include_path[PATH_MAX + 1];
        size_t include_path_len = 0;
        char file_path[PATH_MAX + 1];
        char **result = NULL;
        char **result_next = result;
        int result_count = 0;
        int result_capacity = 0;

        *include_path = 0;

        assert(path);
        la_debug("include_func(%s)", path);

        if(*path != '/')
        {
                if(include_dir)
                {
                        strcat(include_path, include_dir);
                        include_path_len += strlen(include_dir);
                }
        }

        p = strrchr(path, '/');
        if(p > path)
        {
                int len = p - path;


                if((include_path_len > 0) && (*(include_path +
                                                include_path_len - 1) != '/'))
                {
                        strcat(include_path, "/");
                        ++include_path_len;
                }

                strncat(include_path, path, len);
                include_path_len += len;
        }

        if(include_path_len == 0)
        {
                strcpy(include_path, ".");
                include_path_len = 1;
        }

        dp = opendir(include_path);
        if(dp)
        {
                while((dir_entry = readdir(dp)) != NULL)
                {
                        snprintf(file_path, PATH_MAX, "%s/%s", include_path,
                                        dir_entry->d_name);
                        if(lstat(file_path, &stat_buf) != 0)
                                continue;
                        if(!S_ISREG(stat_buf.st_mode))
                                continue;
                        if(fnmatch(path, file_path, FNM_PATHNAME) != 0)
                                continue;

                        if(result_count == result_capacity)
                        {
                                result_capacity += 16;
                                result = (char **)realloc(result, (result_capacity + 1) * sizeof(char *));
                                result_next = result + result_count;
                        }

                        *result_next = strdup(file_path);
                        ++result_next;
                        ++result_count;
                }
                closedir(dp);
        }

        *result_next = NULL;

        return ((const char **)result);
}

/* vim: set autowrite expandtab: */
