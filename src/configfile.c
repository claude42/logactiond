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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <glob.h>

#include <libconfig.h>

#include "ndebug.h"
#include "addresses.h"
#include "commands.h"
#include "configfile.h"
#include "endqueue.h"
#include "logactiond.h"
#include "logging.h"
#include "misc.h"
#include "patterns.h"
#include "properties.h"
#include "rules.h"
#include "sources.h"

la_config_t *la_config = NULL;
int id_counter = 0;

pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Return string for path relative to setting. Return NULL if element does not
 * exist.
 */

static const char*
config_get_string_or_null(const config_setting_t *const setting,
                const char *const name)
{
        assert(setting); assert(name);
        const char *result;
        if (!config_setting_lookup_string(setting, name, &result))
                result = NULL;

        return result;
}

/*
 * Return unsigned int for path relative to setting. Return -1 if element does
 * not exist.
 */

static int
config_get_unsigned_int_or_negative(const config_setting_t *const setting,
                const char *const name)
{
        assert(setting); assert(name);
        int result;
        if (!config_setting_lookup_int(setting, name, &result))
                return -1;

        return result;
}

/*
 * Return string for path relative to setting. Die if element does not exist
 */

static const char*
config_get_string_or_die(const config_setting_t *const setting,
                const char *const name)
{
        assert(setting); assert(name);
        const char *const result = config_get_string_or_null(setting, name);

        if (!result)
                die_hard(false, "Config element %s missing!", name);

        return result;
}

/*
 * Return config_setting_t for path relative to setting. Die if element does
 * not exist
 */

static const config_setting_t *
config_setting_lookup_or_die(const config_setting_t *const setting,
                const char *const path)
{
        assert(setting); assert(path);
        /* TODO: not sure why config_setting_t * (without const) is required
         * here but nowhere else */
        const config_setting_t *const result = config_setting_lookup(
                                (config_setting_t *) setting, path);
        if (!result)
                die_hard(false, "Config element %s missing!", path);

        return result;
}

/* 
 * Return config_setting_t for named element in the "rules" section of the
 * config file
 */

static const config_setting_t *
get_rule(const char *const rule_name)
{
        assert(rule_name);
        assert(la_config);

        return config_setting_lookup(config_lookup(
                                &la_config->config_file,
                                LA_RULES_LABEL), rule_name);
}

/*
 * Returns a config_setting_t to an action within the main actions section -
 * specified by the action_name.
 *
 * Returns NULL in case no pattern with that name exists
 */

static const config_setting_t *
get_action(const char *const action_name)
{
        assert(action_name);
        assert(la_config);

        return config_setting_lookup_or_die(config_lookup(
                                &la_config->config_file,
                                LA_ACTIONS_LABEL), action_name);
}


/*
 * Return config_setting_t for given source name.
 *
 * Return NULL in case of an error -e.g. when source == NULL.
 */

static config_setting_t *
get_source(const char *const source)
{
        if (!source)
                return NULL;

        assert(la_config);

        config_setting_t *const sources_section =
                config_lookup(&la_config->config_file, LA_SOURCES_LABEL);
        if (!sources_section)
                die_hard(false, LA_SOURCES_LABEL " section missing!");

        config_setting_t *result = config_setting_lookup(sources_section,
                        source);

        return  result;
}

/*
 * Return config_setting_t for given rule. Look first in uc_rule, then rule.
 * Die if not found in either definition.
 */

static config_setting_t *
get_source_uc_rule_or_rule(const config_setting_t *const rule,
                const config_setting_t *const uc_rule)
{
        assert(uc_rule);

        config_setting_t *result = get_source(config_get_string_or_null(
                                        uc_rule,
                                        LA_RULE_SOURCE_LABEL));

        if (!result && rule)
                result = get_source(config_get_string_or_null(rule,
                                        LA_RULE_SOURCE_LABEL));

        if (!result)
                die_hard(false, "Source not found for rule %s!",
                                config_setting_name(uc_rule));

        return result;
}

/*
 * Returns name of source - i.e. label reference by "source" item in a rule
 * section.
 */

static const char *
get_source_name(const config_setting_t *const rule,
                const config_setting_t *const uc_rule)
{
        assert(uc_rule);

        const char *result = config_get_string_or_null(uc_rule,
                        LA_RULE_SOURCE_LABEL);

        if (!result && rule)
                result = config_get_string_or_null(rule, LA_RULE_SOURCE_LABEL);

        if (!result)
                die_hard(false, "No source name specified for rule %s!",
                                config_setting_name(uc_rule));

        return result;
}

/*
 * Return the common prefix for the source corresponding to the given rule,
 * NULL if none specified in config file.
 */

static const char *
get_source_prefix(const config_setting_t *const rule,
                const config_setting_t *const uc_rule)
{
        assert(uc_rule);

        const config_setting_t *const source_def =
                get_source_uc_rule_or_rule(rule, uc_rule);

        const char *result;
        if (!config_setting_lookup_string(source_def, LA_SOURCE_PREFIX, &result))
                result = NULL;

        return result;
}

/*
 * Return source location to corresponding rule. Look first in user
 * configuration section, then in rule section.
 */

static const char *
get_source_location(const config_setting_t *const rule,
                const config_setting_t *const uc_rule)
{
        assert(uc_rule);

        const config_setting_t *const source_def =
                get_source_uc_rule_or_rule(rule, uc_rule);

        const char *result;
        if (!config_setting_lookup_string(source_def, LA_SOURCE_LOCATION, &result))
                die_hard(false, "Source location missing for rule %s!",
                                config_setting_name(uc_rule));

        return result;
}

/*
 * Add command for each action's begin command to the begin_commands of
 * the corresponding rule.
 */

static void
compile_actions(la_rule_t *const rule, const config_setting_t *const action_def)
{
        assert_rule(rule); assert(action_def);

        la_debug_func(rule->node.nodename);

        const char *const name = config_setting_name(action_def);
#ifndef NOCOMMANDS
        const char *const initialize = config_get_string_or_null(action_def,
                        LA_ACTION_INITIALIZE_LABEL);
        const char *const shutdown = config_get_string_or_null(action_def,
                        LA_ACTION_SHUTDOWN_LABEL);
#endif /* NOCOMMANDS */
        const char *const begin = config_get_string_or_die(action_def,
                        LA_ACTION_BEGIN_LABEL);
        const char *const end = config_get_string_or_null(action_def,
                        LA_ACTION_END_LABEL);

        const char *const tmp = config_get_string_or_null(action_def,
                        LA_ACTION_NEED_HOST_LABEL);

        la_need_host_t need_host = LA_NEED_HOST_NO;
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
                die_hard(false, "Invalid value \"%s\" for need_host "
                                "parameter!", tmp);

        int quick_shutdown = false;
        config_setting_lookup_bool(action_def, LA_ACTION_QUICK_SHUTDOWN_LABEL, &quick_shutdown);

#ifndef NOCOMMANDS
        if (initialize)
        {
                la_command_t *const template = create_template(name, rule,
                                initialize, shutdown, INT_MAX, false, false);
                convert_both_commands(template);
#ifndef ONLYCLEANUPCOMMANDS
                trigger_command(template);
#endif /* ONLYCLEANUPCOMMANDS */
                if (template->end_string)
                        enqueue_end_command(template, 0);
        }
#endif /* NOCOMMANDS */

        if (begin)
                add_tail(&rule->begin_commands, (kw_node_t *)
                                create_template(name, rule, begin, end,
                                        rule->duration, need_host,
                                        quick_shutdown));
        else
                die_hard(false, "Begin action always required!");

        assert_list(&rule->begin_commands);
}

static void
compile_list_of_actions(la_rule_t *const rule,
                const config_setting_t *const action_def)
{
        assert_rule(rule); assert(action_def);

        la_debug_func(rule->node.nodename);

        const int n_items = config_setting_length(action_def);

        for (int i=0; i<n_items; i++)
        {
                const config_setting_t *list_item =
                        config_setting_get_elem(action_def, i);
                compile_actions(rule, get_action(config_setting_get_string(
                                                list_item)));
        }
}

/*
 * Reads all blacklists assigned to a rule
 */

static void
load_blacklists(la_rule_t *const rule, const config_setting_t *const uc_rule_def)
{
        assert_rule(rule); assert(uc_rule_def);

        la_debug_func(rule->node.nodename);
        /* again unclear why this cast is necessary */
        const config_setting_t *blacklist_reference =
                config_setting_lookup((config_setting_t *) uc_rule_def,
                                LA_BLACKLISTS_LABEL);
        if (!blacklist_reference)
        {
                config_setting_t *const defaults_section =
                        config_lookup(&la_config->config_file, LA_DEFAULTS_LABEL);
                if (defaults_section)
                        blacklist_reference = config_setting_lookup(
                                        defaults_section, LA_BLACKLISTS_LABEL);
        }

        if (!blacklist_reference)
                return;

        const int type = config_setting_type(blacklist_reference);

        if (type == CONFIG_TYPE_STRING)
        {
                kw_node_t *const new = create_node(sizeof *new, 0,
                                config_setting_get_string(blacklist_reference));
                add_tail(&rule->blacklists, new);
        }
        else if (type == CONFIG_TYPE_LIST)
        {
                const int n_items = config_setting_length(
                                blacklist_reference);
                for (int i=0; i<n_items; i++)
                {
                        const config_setting_t *const list_item = 
                                config_setting_get_elem(blacklist_reference, i);
                        kw_node_t *const new = create_node(sizeof *new, 0, 
                                        config_setting_get_string(list_item));
                        add_tail(&rule->blacklists, new);
                }
        }
        else
                die_hard(false, "Element neither string nor list!");
}

/*
 * Return a list of all actions (i.e. struct la_action_s) assigned to a rule
 */

static void
load_actions(la_rule_t *const rule, const config_setting_t *const uc_rule_def)
{
        assert_rule(rule); assert(uc_rule_def);

        la_debug_func(rule->node.nodename);
        /* again unclear why this cast is necessary */
        const config_setting_t *action_reference =
                config_setting_lookup((config_setting_t *) uc_rule_def,
                                LA_RULE_ACTION_LABEL);
        if (!action_reference)
        {
                config_setting_t *const defaults_section =
                        config_lookup(&la_config->config_file, LA_DEFAULTS_LABEL);
                if (!defaults_section)
                        die_hard(false, "No action specified for %s!",
                                        config_setting_name(uc_rule_def));
                action_reference = config_setting_lookup(defaults_section,
                                LA_RULE_ACTION_LABEL);
                if (!action_reference)
                        die_hard(false, "No action specified for %s!",
                                        config_setting_name(uc_rule_def));
        }

        const int type = config_setting_type(action_reference);

        if (type == CONFIG_TYPE_STRING)
                compile_actions(rule, get_action(
                                        config_setting_get_string(
                                                action_reference)));
        else if (type == CONFIG_TYPE_LIST)
                compile_list_of_actions(rule, action_reference);
        else
                die_hard(false, "Element neither string nor list!");
}

static void
load_patterns(la_rule_t *const rule, const config_setting_t *const rule_def, 
                const config_setting_t *const uc_rule_def)
{
        assert_rule(rule); assert(uc_rule_def);

        la_debug_func(rule->node.nodename);

        const config_setting_t *patterns;

        /* again unclear why this cast is necessary */
        patterns = config_setting_lookup((config_setting_t *)
                        uc_rule_def, LA_RULE_PATTERNS_LABEL);
        if (!patterns && rule_def)
                patterns = config_setting_lookup_or_die(rule_def,
                                LA_RULE_PATTERNS_LABEL);

        if (!patterns)
                die_hard(false, "No patterns specified for %s!",
                                config_setting_name(rule_def));

        const int n = config_setting_length(patterns);
        if (n < 0)
                die_hard(false, "No patterns specified for %s!",
                                config_setting_name(rule_def));

        for (int i=0; i<n; i++)
        {
                const char *const item = config_setting_get_string_elem(patterns, i);

                la_pattern_t *pattern = create_pattern(item, i, rule);

                add_tail(&rule->patterns, (kw_node_t *) pattern);
        }
        assert_list(&rule->patterns);
}


static void
compile_address_list_port_domainname(kw_list_t *const list,
                const config_setting_t *const setting, const in_port_t port,
                const bool domainname)
{
        if (!setting)
                return;

        la_debug_func(config_setting_name(setting));

        assert_list(list);

        const int n = config_setting_length(setting);
        for (int i=0; i<n; i++)
        {
                const config_setting_t *const elem =
                        config_setting_get_elem(setting, i);
                const char *const ip = config_setting_get_string(elem);
                if (!ip)
                        die_hard(false, "Only strings allowed in address list!");

                la_address_t *const address = create_address_port(ip, port);
                if (!address)
                        die_hard(false, "Invalid IP address %s!", ip);

                if (domainname)
                        (void) query_domainname(address);

                la_debug("compile_address_list_port_domainname(%s)=%s(%s)",
                                config_setting_name(setting),
                                address->domainname, address->text);
                add_tail(list, (kw_node_t *) address);
        }
        assert_list(list);

        return;
}

static void
compile_address_list(kw_list_t *const list,
                const config_setting_t *const setting)
{
        compile_address_list_port_domainname(list, setting, 0, false);
}

/*
 * Add all properties which exist in a properties section the given section to
 * the given properties list. Do not add properties which already exist in the
 * list.
 */

static void
load_properties(kw_list_t *const properties, const config_setting_t *const section)
{
        assert_list(properties); assert(section);

        la_debug_func(config_setting_name(section));

        const config_setting_t *const properties_section =
                config_setting_get_member(section, LA_PROPERTIES_LABEL);

        if (!properties_section)
                return;

        const int n = config_setting_length(properties_section);
        for (int i=0; i<n; i++)
        {
                const config_setting_t *const elem =
                        config_setting_get_elem(properties_section, i);
                const char *const name = config_setting_name(elem);
                if (!name)
                        die_hard(false, "Property without a name?!");
                const char *const value = config_setting_get_string(elem);
                if (!value)
                        die_hard(false, "Only strings allowed for properties!");

                /* if property with same name already exists, do nothing (as
                 * this could be a standard use case, e.g. rule property
                 * overrides default property etc. */
                if (get_property_from_property_list(properties, name))
                        continue;

                la_property_t *const property = create_property_from_config(name, value);

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
get_rule_string(const config_setting_t *const rule_def,
                const config_setting_t *const uc_rule_def, const char *const name)
{
        assert(uc_rule_def); assert(name);

        const char *result = config_get_string_or_null(uc_rule_def, name);

        if (!result && rule_def)
                result = config_get_string_or_null(rule_def, name);

        return result;
}

/*
 * Returns a rule parameter. Always tries local ("uc_rule") definition first.
 * If that doesn't exist, tries the normal rules ("rule") definition. Returns
 * NULL in case neither exists.
 */

static int
get_rule_unsigned_int(const config_setting_t *const rule_def,
                const config_setting_t *const uc_rule_def, const char *const name)
{
        assert(uc_rule_def); assert(name);

        int result = config_get_unsigned_int_or_negative(uc_rule_def, name);

        if (result < 0 && rule_def)
                result = config_get_unsigned_int_or_negative(rule_def, name);

        return result;
}

/*
 * Create new source, add it to list of sources, begin watching.
 */

static la_source_group_t *
create_file_sources(const config_setting_t *const rule_def,
                const config_setting_t *const uc_rule_def)
{
        assert(uc_rule_def);
        assert(la_config); assert_list(&la_config->source_groups);

        const char *const name = get_source_name(rule_def, uc_rule_def);
        const char *const location = get_source_location(rule_def, uc_rule_def);
        const char *const prefix = get_source_prefix(rule_def, uc_rule_def);

        /* First create single source_group */
        la_source_group_t *result = create_source_group(name, location, prefix);

        glob_t pglob;
        if (glob(location, 0, NULL, &pglob))
                la_log(LOG_ERR, "Source \"%s\" - file \"%s\" not found.", name,
                                location);

        /* Second create source objects for all matching files */
        for (size_t i = 0; i < pglob.gl_pathc; i++)
        {
                la_source_t *src = create_source(result, pglob.gl_pathv[i]);
                add_tail(&result->sources, (kw_node_t *) src);
        }

        globfree(&pglob);

        add_tail(&la_config->source_groups, (kw_node_t *) result);

        return result;
}

/*
 * Add systemd unit to systemd_source's list of systemd unit. Makes sure, a
 * unit with the same name isn't added more than once.
 */

#if HAVE_LIBSYSTEMD
#ifndef NOWATCH
static void
add_systemd_unit_to_list(const char *const systemd_unit)
{
        assert(systemd_unit);

        kw_list_t *const ex_systemd_units = &la_config->systemd_source_group->systemd_units;
        assert_list(ex_systemd_units);

        FOREACH(kw_node_t, tmp, ex_systemd_units)
        {
                if (!strcmp(systemd_unit, tmp->nodename))
                        return;
        }

        kw_node_t *const node = create_node(sizeof *node, 0, systemd_unit);
        add_tail(ex_systemd_units, node);
}
#endif /* NOWATCH */

/*
 * Adds a systemd unit.
 *
 * Initializes la_config->systemd_source if it didn't exist so far.
 */

static la_source_group_t *
create_systemd_unit(const char *const systemd_unit)
{
        assert(systemd_unit);
        assert(la_config);
        if (!la_config->systemd_source_group)
        {
                /* TODO: set location also to NULL */
                la_config->systemd_source_group = create_source_group("systemd",
                                "systemd", NULL);
                la_source_t *systemd_source = create_source(
                                la_config->systemd_source_group, "systemd");
                add_tail(&la_config->systemd_source_group->sources,
                                (kw_node_t *) systemd_source);
        }
#ifndef NOWATCH
        add_systemd_unit_to_list(systemd_unit);
#endif /* NOWATCH */

        return la_config->systemd_source_group;
}
#endif /* HAVE_LIBSYSTEMD */

/*
 * Load a single rule
 *
 * uc_rule_def - user configuration where rule is enabled in local section of
 * the config file
 */

static bool
load_single_rule(const config_setting_t *const uc_rule_def)
{
        assert(uc_rule_def);

        int enabled;
        if (config_setting_lookup_bool(uc_rule_def, LA_ENABLED_LABEL,
                                &enabled) == CONFIG_FALSE)
                enabled = false;

        const char *const name = config_setting_name(uc_rule_def);
        la_debug_func(name);
        const config_setting_t *const rule_def = get_rule(name);

        const char *systemd_unit;
        la_source_group_t *source_group;
#if HAVE_LIBSYSTEMD
        systemd_unit = get_rule_string(rule_def, uc_rule_def,
                        LA_RULE_SYSTEMD_UNIT_LABEL);

        if (systemd_unit)
        {
                source_group = create_systemd_unit(systemd_unit);
        }
        else
#endif /* HAVE_LIBSYSTEMD */
        {
                systemd_unit = NULL; /* necessary if HAVE_LIBSYSTEMD==0 */
                source_group = find_source_group_by_name(get_source_name(rule_def,
                                        uc_rule_def));

                if (!source_group)
                        source_group = create_file_sources(rule_def, uc_rule_def);
        }

        /* get parameters either from rule or uc_rule */
        const int threshold = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_THRESHOLD_LABEL);
        const int period = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_PERIOD_LABEL);
        const int duration = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_DURATION_LABEL);

        const int dnsbl_duration = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_DNSBL_DURATION_LABEL);

        /* meta_enabled could either be 1 (enabled for rule), 0 (disabled for
         * rule) or -1 (not specified in rule, use default) */
        int meta_enabled = -1;
        if (rule_def && !config_setting_lookup_bool(rule_def,
                                LA_META_ENABLED_LABEL, &meta_enabled))
        {
                if (!config_setting_lookup_bool(uc_rule_def,
                                        LA_META_ENABLED_LABEL, &meta_enabled))
                        meta_enabled = -1;
        }

        const int meta_period = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_META_PERIOD_LABEL);
        const int meta_factor = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_META_FACTOR_LABEL);
        const int meta_max = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_META_MAX_LABEL);

        /* dnsbl_enabled can only be set in the local section, not in the rules
         * section and also not in the defaults section! */
        int dnsbl_enabled = false;
        config_setting_lookup_bool(uc_rule_def, LA_DNSBL_ENABLED_LABEL, &dnsbl_enabled);

        const char *const service = get_rule_string(rule_def, uc_rule_def,
                        LA_SERVICE_LABEL);

        la_rule_t *const new_rule = create_rule(enabled, name, source_group,
                        threshold, period, duration, dnsbl_duration,
                        meta_enabled, meta_period, meta_factor, meta_max,
                        dnsbl_enabled, service, systemd_unit);
        assert_rule(new_rule);

        if (new_rule->enabled)
                la_log(LOG_INFO, "Enabling rule \"%s\".", name);

        /* Properties from uc_rule_def have priority over those from
         * rule_def */
        load_properties(&new_rule->properties, uc_rule_def);
        if (rule_def)
                load_properties(&new_rule->properties, rule_def);

        /* Patterns from uc_rule_def have priority over those from rule_def */
        load_patterns(new_rule, rule_def, uc_rule_def);

        /* actions are only taken from uc_rule_def (or default settings) */
        load_actions(new_rule, uc_rule_def);

        /* blacklists are only taken from uc_rule_def (or default settings) */
        load_blacklists(new_rule, uc_rule_def);

        add_tail(&source_group->rules, (kw_node_t *) new_rule);

        return enabled;
}


static int
load_rules(void)
{
        la_debug_func(NULL);
        assert(la_config);

        const config_setting_t *const local_section = 
                config_lookup(&la_config->config_file, LA_LOCAL_LABEL);
        if (!local_section)
                return 0;

        const int n = config_setting_length(local_section);
        if (n < 0)
                return 0;

        init_list(&la_config->source_groups);

        int num_rules_enabled = 0;
        for (int i=0; i<n; i++)
        {
                config_setting_t *uc_rule = 
                        config_setting_get_elem(local_section, i);

                if (load_single_rule(uc_rule))
                        num_rules_enabled++;
        }

        return num_rules_enabled;
}

static void
load_remote_settings(void)
{
        la_debug_func(NULL);
        assert(la_config);

        la_config->remote_enabled = false;

        config_setting_t *const remote_section =
                config_lookup(&la_config->config_file, LA_REMOTE_LABEL);

        if (!remote_section)
                return;
        if (!config_setting_lookup_bool(remote_section, LA_ENABLED_LABEL,
                                &la_config->remote_enabled))
                return;
        if (!la_config->remote_enabled)
                return;

        la_config->remote_enabled = true;

        la_config->remote_secret = xstrdup(config_get_string_or_null(remote_section,
                        LA_REMOTE_SECRET_LABEL));
        la_config->remote_secret_changed = true;
        if (xstrlen(la_config->remote_secret) == 0)
                die_hard(false, "Remote handling enabled but no secret specified");

        const config_setting_t *const receive_from = config_setting_lookup(
                        remote_section, LA_REMOTE_RECEIVE_FROM_LABEL);
        init_list(&la_config->remote_receive_from);
        compile_address_list_port_domainname(&la_config->remote_receive_from,
                        receive_from, 0, true);

        la_config->remote_bind = xstrdup(config_get_string_or_null(remote_section,
                        LA_REMOTE_BIND_LABEL));

        la_config->remote_port = config_get_unsigned_int_or_negative(
                        remote_section, LA_REMOTE_PORT_LABEL);
        if (la_config->remote_port < 0)
                la_config->remote_port = DEFAULT_PORT;

        /* Must obviously go after initialization of remote port... */
        const config_setting_t *const send_to = config_setting_lookup(remote_section,
                        LA_REMOTE_SEND_TO_LABEL);
        init_list(&la_config->remote_send_to);
        compile_address_list_port_domainname(&la_config->remote_send_to, send_to,
                        la_config->remote_port, false);

}

static void
load_file_settings(void)
{
        la_debug_func(NULL);
        assert(la_config);

        config_setting_t *const files_section =
                config_lookup(&la_config->config_file, LA_FILES_LABEL);

        if (files_section)
        {
                la_config->fifo_path = xstrdup(
                                config_get_string_or_null(files_section,
                                        LA_FILES_FIFO_PATH_LABEL));
                if (!la_config->fifo_path)
                        la_config->fifo_path = xstrdup(FIFOFILE);

                la_config->fifo_user = determine_uid(
                                config_get_string_or_null(files_section,
                                        LA_FILES_FIFO_USER_LABEL));
                la_config->fifo_group = determine_gid(
                                config_get_string_or_null(files_section,
                                        LA_FILES_FIFO_GROUP_LABEL));
                if ((la_config->fifo_user == UINT_MAX ||
                                la_config->fifo_group == UINT_MAX) &&
                                la_config->fifo_user != la_config->fifo_group)
                        die_hard(false, "Must specify either both fifo_user and "
                                        "fifo_group or neither!");

                int mask = 0;
                if (config_setting_lookup_int(files_section, LA_FILES_FIFO_MASK_LABEL, &mask))
                        la_config->fifo_mask = mask;
                else
                        la_config->fifo_mask = 0;
        }
        else
        {
                la_config->fifo_path = xstrdup(FIFOFILE);
                la_config->fifo_user = 0;
                la_config->fifo_group = 0;
                la_config->fifo_mask = 0;
        }
}

static void
load_defaults(void)
{
        la_debug_func(NULL);
        assert(la_config);

        const config_setting_t *const defaults_section =
                config_lookup(&la_config->config_file, LA_DEFAULTS_LABEL);

        init_list(&la_config->default_properties);
        init_list(&la_config->ignore_addresses);

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
                la_config->default_dnsbl_duration =
                        config_get_unsigned_int_or_negative(defaults_section,
                                        LA_DNSBL_DURATION_LABEL);
                if (la_config->default_dnsbl_duration == -1)
                        la_config->default_dnsbl_duration =
                                la_config->default_duration;


                if (!config_setting_lookup_bool(defaults_section,
                                        LA_META_ENABLED_LABEL,
                                        &(la_config->default_meta_enabled)))
                        la_config->default_meta_enabled = DEFAULT_META_ENABLED;

                la_config->default_meta_period =
                        config_get_unsigned_int_or_negative(defaults_section,
                                        LA_META_PERIOD_LABEL);
                if (la_config->default_meta_period == -1)
                        la_config->default_meta_period = DEFAULT_META_PERIOD;

                la_config->default_meta_factor =
                        config_get_unsigned_int_or_negative(defaults_section,
                                        LA_META_FACTOR_LABEL);
                if (la_config->default_meta_factor == -1)
                        la_config->default_meta_factor = DEFAULT_META_FACTOR;

                la_config->default_meta_max =
                        config_get_unsigned_int_or_negative(defaults_section,
                                        LA_META_MAX_LABEL);
                if (la_config->default_meta_max == -1)
                        la_config->default_meta_max = DEFAULT_META_MAX;

                load_properties(&la_config->default_properties, defaults_section);

                const config_setting_t *ignore = config_setting_get_member(
                                defaults_section, LA_IGNORE_LABEL);
                compile_address_list_port_domainname(&la_config->ignore_addresses,
                                ignore, 0, true);
        }
        else
        {
                la_config->default_threshold = DEFAULT_THRESHOLD;
                la_config->default_period = DEFAULT_PERIOD;
                la_config->default_duration = DEFAULT_DURATION;
                la_config->default_meta_enabled = DEFAULT_META_ENABLED;
                la_config->default_meta_period = DEFAULT_META_PERIOD;
                la_config->default_meta_max = DEFAULT_META_MAX;
        }
}

static const char ** include_func(config_t *config, const char *const include_dir,
                const char *const path, const char **const error);

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
                die_hard(true, "Can't set mutex attributes");
        pthread_mutex_init(&config_mutex, &config_mutex_attr);
}*/

bool
init_la_config(const char *filename)
{
        if (!filename)
                filename = CONFIG_FILE;

        la_log(LOG_INFO, "Loading configuration from \"%s/%s\".", CONF_DIR,
                        filename);

        if (!la_config)
                la_config = xmalloc0(sizeof *la_config);

        config_init(&la_config->config_file);

        config_set_include_func(&la_config->config_file, include_func);

        if (!config_read_file(&la_config->config_file, filename))
        {
                const char *const error_file =
                        config_error_file(&la_config->config_file);

                if (error_file)
                        la_log(LOG_ERR, "%s:%d - %s!",
                                        config_error_file(&la_config->config_file),
                                        config_error_line(&la_config->config_file),
                                        config_error_text(&la_config->config_file));
                else
                        la_log(LOG_ERR, "%s!", config_error_text(&la_config->config_file));

                return false;
        }

        return true;
}

void
load_la_config(void)
{
        char *die_str = NULL;

#ifndef CLIENTONLY
        xpthread_mutex_lock(&config_mutex);
#endif /* CLIENTONLY */

                load_defaults();
                if (!load_rules())
                {
                        die_str = "No rules enabled!";
                        goto cleanup;
                }
                load_remote_settings();
                load_file_settings();

                config_destroy(&la_config->config_file);

        la_config->total_clocks = la_config->invocation_count = 0;
        la_config->total_et_invs = la_config->total_et_cmps = 0;

cleanup:
#ifndef CLIENTONLY
        xpthread_mutex_unlock(&config_mutex);
#endif /* CLIENTONLY */
        if (die_str)
                die_hard(false, die_str);
}

void
unload_la_config(void)
{
        la_debug_func(NULL);
        assert(la_config);

        /* In case shutdown is ongoing, don't bother with a mutex (which might
         * not have been correctly unlocked. OTOH, when reloading, it's
         * absolutely necessary to lock the mutex.
         */
#ifndef CLIENTONLY
        if (!shutdown_ongoing)
                xpthread_mutex_lock(&config_mutex);
#endif /* CLIENTONLY */

        empty_source_group_list(&la_config->source_groups);
#if HAVE_LIBSYSTEMD
        free_source_group(la_config->systemd_source_group);
        la_config->systemd_source_group = NULL;
#endif /* HAVE_LIBSYSTEMD */
        empty_property_list(&la_config->default_properties);
        empty_address_list(&la_config->ignore_addresses);
        free(la_config->remote_secret);
        empty_address_list(&la_config->remote_receive_from);
        empty_address_list(&la_config->remote_send_to);
        free(la_config->remote_bind);
        la_config->remote_bind = NULL;
        free(la_config->fifo_path);
        la_config->fifo_path = NULL;

#ifndef CLIENTONLY
        if (!shutdown_ongoing)
                xpthread_mutex_unlock(&config_mutex);
#endif /* CLIENTONLY */
}

/*
 * This include_func() implementation simply ignores include_dir / assumes that
 * it's empty.
 */

static const char **
include_func(config_t *config, const char *const include_dir,
                const char *const path, const char **const error)
{
        assert(path);
        la_debug_func(path);

        glob_t pglob;

        if (glob(path, 0, NULL, &pglob))
        {
                *error = strerror(errno);
                return NULL;
        }

        char **result = NULL;
        char **result_next = NULL;
        int result_count = 0;
        int result_capacity = 0;

        for (size_t i = 0; i < pglob.gl_pathc; i++)
        {
                const char *const file_path = pglob.gl_pathv[i];
                la_vdebug("%lu. file_path=%s", i, file_path);

                struct stat stat_buf;
                if (lstat(file_path, &stat_buf) != 0)
                        continue;
                if (!S_ISREG(stat_buf.st_mode))
                        continue;

                /* Allocate more memory if necessary */
                if (result_count == result_capacity)
                {
                        result_capacity += 16;
                        result = (char **) xrealloc(result,
                                        (result_capacity + 1) *
                                        sizeof (char *));
                        result_next = result + result_count;
                }

                *result_next = xstrdup(file_path);
                result_next++;
                result_count++;
        }

        globfree(&pglob);

        if (!result_count)
        {
                *error = strerror(ENOENT);
                return NULL;
        }

        *result_next = NULL;

        return ((const char **) result);
}

int
get_unique_id(void)
{
        return ++id_counter;
}


/* vim: set autowrite expandtab: */
