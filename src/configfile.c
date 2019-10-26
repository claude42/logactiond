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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdbool.h>

#include <sys/types.h>
#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/stat.h>

#include <libconfig.h>

#include "logactiond.h"

la_config_t *la_config = NULL;

pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Return string for path relative to setting. Return NULL if element does not
 * exist.
 */

static const char*
config_get_string_or_null(const config_setting_t *setting, const char *name)
{
        assert(setting); assert(name);
        const char* result;
        if (!config_setting_lookup_string(setting, name, &result))
                result = NULL;

        return result;
}

/*
 * Return unsigned int for path relative to setting. Return -1 if element does
 * not exist.
 */

static int
config_get_unsigned_int_or_negative(const config_setting_t *setting,
                const char *name)
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
config_get_string_or_die(const config_setting_t *setting, const char *name)
{
        assert(setting); assert(name);
        const char* result = config_get_string_or_null(setting, name);

        if (!result)
                die_hard("Config element %s missing!", name);

        return result;
}

/*
 * Return config_setting_t for path relative to setting. Die if element does
 * not exist
 */

static const config_setting_t *
config_setting_lookup_or_die(const config_setting_t *setting,
                const char *path)
{
        assert(setting); assert(path);
        const config_setting_t *result;
        /* TODO: not sure why config_setting_t * (without const) is required
         * here but nowhere else */
        result = config_setting_lookup((config_setting_t *) setting, path);
        if (!result)
                die_hard("Config element %s missing!", path);

        return result;
}

/* 
 * Return config_setting_t for named element in the "rules" section of the
 * config file
 */

static const config_setting_t *
get_rule(const char *rule_name)
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
get_action(const char *action_name)
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
 *
 *
 * TODO: not needed anymore?
 */

static config_setting_t *
get_source(const char *source)
{
        assert(la_config);

        config_setting_t *sources_section;
        config_setting_t *result;

        if (!source)
                return NULL;

        sources_section = config_lookup(&la_config->config_file, LA_SOURCES_LABEL);
        if (!sources_section)
                die_hard(LA_SOURCES_LABEL " section missing!");

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
        assert(uc_rule);

        config_setting_t *result;

        result = get_source(config_get_string_or_null(uc_rule,
                                LA_RULE_SOURCE_LABEL));

        if (!result && rule)
                result = get_source(config_get_string_or_null(rule,
                                        LA_RULE_SOURCE_LABEL));

        if (!result)
                die_hard("Source not found for rule %s!",
                                config_setting_name(uc_rule));

        return result;
}

/*
 * Returns name of source - i.e. label reference by "source" item in a rule
 * section.
 */

static const char *
get_source_name(const config_setting_t *rule, const config_setting_t *uc_rule)
{
        assert(uc_rule);

        const char *result;

        result = config_get_string_or_null(uc_rule, LA_RULE_SOURCE_LABEL);

        if (!result && rule)
                result = config_get_string_or_null(rule, LA_RULE_SOURCE_LABEL);

        if (!result)
                die_hard("No source name specified for rule %s!",
                                config_setting_name(uc_rule));

        return result;
}

/*
 * Return the common prefix for the source corresponding to the given rule,
 * NULL if none specified in config file.
 */

static const char *
get_source_prefix(const config_setting_t *rule, const config_setting_t *uc_rule)
{
        assert(uc_rule);

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

static const char *
get_source_location(const config_setting_t *rule, const config_setting_t *uc_rule)
{
        assert(uc_rule);

        config_setting_t *source_def;
        const char *result;

        source_def = get_source_uc_rule_or_rule(rule, uc_rule);

        if (!config_setting_lookup_string(source_def, LA_SOURCE_LOCATION, &result))
                die_hard("Source location missing for rule %s!",
                                config_setting_name(uc_rule));

        return result;
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
#ifndef NOCOMMANDS
        const char *initialize = config_get_string_or_null(action_def,
                        LA_ACTION_INITIALIZE_LABEL);
        const char *shutdown = config_get_string_or_null(action_def,
                        LA_ACTION_SHUTDOWN_LABEL);
#endif /* NOCOMMANDS */
        const char *begin = config_get_string_or_die(action_def,
                        LA_ACTION_BEGIN_LABEL);
        const char *end = config_get_string_or_null(action_def,
                        LA_ACTION_END_LABEL);

        const char *tmp = config_get_string_or_null(action_def,
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
                die_hard("Invalid value \"%s\" for need_host "
                                "parameter!", tmp);

#ifndef NOCOMMANDS
        if (initialize)
        {
                la_command_t *template = create_template(name, rule,
                                initialize, shutdown, INT_MAX, false);
#ifndef ONLYCLEANUPCOMMANDS
                convert_both_commands(template);
                trigger_command(template);
#endif /* ONLYCLEANUPCOMMANDS */
                if (template->end_string)
                        enqueue_end_command(template, 0);
        }
#endif /* NOCOMMANDS */

        if (begin)
                add_tail(rule->begin_commands, (kw_node_t *)
                                create_template(name, rule, begin, end,
                                        rule->duration, need_host));
        else
                die_hard("Begin action always required!");

        assert_list(rule->begin_commands);
}

static void
compile_list_of_actions(la_rule_t *rule,
                const config_setting_t *action_def)
{
        assert_rule(rule); assert(action_def);

        la_debug("compile_list_of_actions(%s)", rule->name);

        unsigned int n_items = config_setting_length(action_def);

        for (unsigned int i=0; i<n_items; i++)
        {
                config_setting_t *list_item =
                        config_setting_get_elem(action_def, i);
                compile_actions(rule, get_action(config_setting_get_string(
                                                list_item)));
        }
}

/*
 * Reads all blacklists assigned to a rule
 */

static void
load_blacklists(la_rule_t *rule, const config_setting_t *uc_rule_def)
{
        assert_rule(rule); assert(uc_rule_def);

        la_debug("load_blacklists(%s)", rule->name);
        const config_setting_t *blacklist_reference;

        /* again unclear why this cast is necessary */
        blacklist_reference = config_setting_lookup((config_setting_t *)
                        uc_rule_def, LA_BLACKLISTS_LABEL);
        if (!blacklist_reference)
        {
                config_setting_t *defaults_section =
                        config_lookup(&la_config->config_file, LA_DEFAULTS_LABEL);
                if (defaults_section)
                        blacklist_reference = config_setting_lookup(
                                        defaults_section, LA_BLACKLISTS_LABEL);
        }

        if (!blacklist_reference)
                return;

        int type = config_setting_type(blacklist_reference);

        if (type == CONFIG_TYPE_STRING)
        {
                kw_node_t *new = xmalloc(sizeof(kw_node_t));
                new->name = xstrdup(config_setting_get_string(
                                        blacklist_reference));
                add_tail(rule->blacklists, new);
        }
        else if (type == CONFIG_TYPE_LIST)
        {
                unsigned int n_items = config_setting_length(
                                blacklist_reference);
                for (unsigned int i=0; i<n_items; i++)
                {
                        config_setting_t *list_item = 
                                config_setting_get_elem(blacklist_reference, i);
                        kw_node_t *new = xmalloc(sizeof(kw_node_t));
                        new->name = xstrdup(config_setting_get_string(
                                                list_item));
                        add_tail(rule->blacklists, new);
                }
        }
        else
                die_hard("Element neither string nor list!");
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
                        die_hard("No action specified for %s!",
                                        config_setting_name(rule));
                action_reference = config_setting_lookup(defaults_section,
                                LA_RULE_ACTION_LABEL);
                if (!action_reference)
                        die_hard("No action specified for %s!",
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
                die_hard("Element neither string nor list!");
}

static void
load_patterns(la_rule_t *rule, const config_setting_t *rule_def, 
                const config_setting_t *uc_rule_def)
{
        assert_rule(rule); assert(uc_rule_def);

        la_debug("load_patterns(%s)", rule->name);

        const config_setting_t *patterns;

        /* again unclear why this cast is necessary */
        patterns = config_setting_lookup((config_setting_t *)
                        uc_rule_def, LA_RULE_PATTERNS_LABEL);
        if (!patterns && rule_def)
                patterns = config_setting_lookup_or_die(rule_def,
                                LA_RULE_PATTERNS_LABEL);

        if (!patterns)
                die_hard("No patterns specified for %s!",
                                config_setting_name(rule_def));

        int n = config_setting_length(patterns);
        if (n < 0)
                die_hard("No patterns specified for %s!",
                                config_setting_name(rule_def));

        for (unsigned int i=0; i<n; i++)
        {
                const char *item = config_setting_get_string_elem(patterns, i);

                la_pattern_t *pattern = create_pattern(item, i, rule);

                add_tail(rule->patterns, (kw_node_t *) pattern);
        }
        assert_list(rule->patterns);
}


static void
compile_address_list_port(kw_list_t *list,
                const config_setting_t *setting, in_port_t port)
{
        assert_list(list); assert(setting);

        la_debug("compile_address_list(%s)", config_setting_name(setting));

        if (!setting)
                return;

        unsigned int n = config_setting_length(setting);
        for (unsigned int i=0; i<n; i++)
        {
                config_setting_t *elem =
                        config_setting_get_elem(setting, i);
                const char *ip = config_setting_get_string(elem);
                if (!ip)
                        die_hard("Only strings allowed in address list!");

                la_address_t *address = create_address_port(ip, port);
                if (!address)
                        die_err("Invalid IP address %s!", ip);

                la_vdebug("compile_address_list(%s)=%s",
                                config_setting_name(setting), address->text);
                add_tail(list, (kw_node_t *) address);
        }
        assert_list(list);

        return;
}

static void
compile_address_list(kw_list_t *list,
                const config_setting_t *setting)
{
        compile_address_list_port(list, setting, 0);
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

        unsigned int n = config_setting_length(properties_section);
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

                /* if property with same name already exists, do nothing (as
                 * this could be a standard use case, e.g. rule property
                 * overrides default property etc. */
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
get_rule_unsigned_int(const config_setting_t *rule_def,
                const config_setting_t *uc_rule_def, const char *name)
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

static la_source_t *
create_file_source(const config_setting_t *rule_def,
                const config_setting_t *uc_rule_def)
{
        assert(uc_rule_def);
        assert(la_config); assert_list(la_config->sources);

        const char *location = get_source_location(rule_def, uc_rule_def);
        const char *prefix = get_source_prefix(rule_def, uc_rule_def);

        la_source_t *result = create_source(get_source_name(rule_def, uc_rule_def),
                        location, prefix);
        assert_source(result);
        add_tail(la_config->sources, (kw_node_t *) result);

        return result;
}

/*
 * Add systemd unit to systemd_source's list of systemd unit. Makes sure, a
 * unit with the same name isn't added more than once.
 */

#if HAVE_LIBSYSTEMD
#ifndef NOWATCH
static void
add_systemd_unit_to_list(const char *systemd_unit)
{
        assert(systemd_unit);
        assert(la_config); assert_source(la_config->systemd_source);
        assert_list(la_config->systemd_source->systemd_units);

        for (kw_node_t *tmp = &(la_config->systemd_source->systemd_units)->head;
                        (tmp = tmp->succ->succ ? tmp->succ : NULL);)
        {
                if (!strcmp(systemd_unit, tmp->name))
                        return;
        }

        kw_node_t *node = xmalloc(sizeof(kw_node_t));
        node->name = xstrdup(systemd_unit);
        add_tail(la_config->systemd_source->systemd_units, node);
}
#endif /* NOWATCH */

/*
 * Adds a systemd unit.
 *
 * Initializes la_config->systemd_source if it didn't exist so far.
 */

static la_source_t *
create_systemd_unit(const char *systemd_unit)
{
        assert(systemd_unit);
        assert(la_config);
        if (!la_config->systemd_source)
        {
                /* TODO: set location also to NULL */
                la_config->systemd_source = create_source("systemd",
                                "systemd", NULL);
                la_config->systemd_source->systemd_units = xcreate_list();
        }
#ifndef NOWATCH
        add_systemd_unit_to_list(systemd_unit);
#endif /* NOWATCH */

        return la_config->systemd_source;
}
#endif /* HAVE_LIBSYSTEMD */

/*
 * Load a single rule
 *
 * uc_rule_def - user configuration where rule is enabled in local section of
 * the config file
 */

static void
load_single_rule(const config_setting_t *uc_rule_def)
{
        assert(uc_rule_def);
        la_rule_t *new_rule;
        la_source_t *source;

        char *name = config_setting_name(uc_rule_def);
        la_debug("load_single_rule(%s)", name);
        const config_setting_t *rule_def = get_rule(name);

        const char *systemd_unit;
#if HAVE_LIBSYSTEMD
        systemd_unit = get_rule_string(rule_def, uc_rule_def,
                        LA_RULE_SYSTEMD_UNIT_LABEL);

        if (systemd_unit)
        {
                source = create_systemd_unit(systemd_unit);
        }
        else
#endif /* HAVE_LIBSYSTEMD */
        {
                systemd_unit = NULL; /* necessary if HAVE_LIBSYSTEMD==0 */
                source = find_source_by_location(get_source_location(rule_def,
                                        uc_rule_def));

                if (!source)
                        source = create_file_source(rule_def, uc_rule_def);
        }

        assert_source(source);

        /* get parameters either from rule or uc_rule */
        int threshold = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_THRESHOLD_LABEL);
        int period = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_PERIOD_LABEL);
        int duration = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_DURATION_LABEL);

        /* meta_enabled could either be 1 (enabled for rule), 0 (disabled for
         * rule) or -1 (not specified in rule, use default) */
        int meta_enabled;
        if (!config_setting_lookup_bool(rule_def, LA_META_ENABLED_LABEL,
                                &meta_enabled))
        {
                if (!config_setting_lookup_bool(uc_rule_def,
                                        LA_META_ENABLED_LABEL, &meta_enabled))
                        meta_enabled = -1;
        }

        int meta_period = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_META_PERIOD_LABEL);
        int meta_factor = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_META_FACTOR_LABEL);
        int meta_max = get_rule_unsigned_int(rule_def, uc_rule_def,
                        LA_META_MAX_LABEL);

        /* dnsbl_enabled can only be set in the local section, not in the rules
         * section and also not in the defaults section! */
        int dnsbl_enabled = false;
        config_setting_lookup_bool(uc_rule_def, LA_DNSBL_ENABLED_LABEL, &dnsbl_enabled);

        const char *service = get_rule_string(rule_def, uc_rule_def,
                        LA_SERVICE_LABEL);

        la_log(LOG_INFO, "Enabling rule \"%s\".", name);
        new_rule = create_rule(name, source, threshold, period, duration,
                        meta_enabled, meta_period, meta_factor, meta_max,
                        dnsbl_enabled, service, systemd_unit);
        assert_rule(new_rule);

        /* Properties from uc_rule_def have priority over those from
         * rule_def */
        load_properties(new_rule->properties, uc_rule_def);
        if (rule_def)
                load_properties(new_rule->properties, rule_def);

        /* Patterns from uc_rule_def have priority over those from rule_def */
        load_patterns(new_rule, rule_def, uc_rule_def);

        /* actions are only taken from uc_rule_def (or default settings) */
        load_actions(new_rule, uc_rule_def);

        /* blacklists are only taken from uc_rule_def (or default settings) */
        load_blacklists(new_rule, uc_rule_def);

        add_tail(source->rules, (kw_node_t *) new_rule);
}


static unsigned int
load_rules(void)
{
        la_debug("load_rules()");
        assert(la_config);

        config_setting_t *local_section = 
                config_lookup(&la_config->config_file, LA_LOCAL_LABEL);
        if (!local_section)
                return 0;

        int n = config_setting_length(local_section);
        if (n < 0)
                return 0;

        la_config->sources = xcreate_list();

        int num_rules_enabled = 0;
        for (int i=0; i<n; i++)
        {
                config_setting_t *uc_rule = 
                        config_setting_get_elem(local_section, i);

                int enabled;
                if (config_setting_lookup_bool(uc_rule, LA_ENABLED_LABEL,
                                        &enabled) == CONFIG_TRUE && enabled)
                {
                        num_rules_enabled++;
                        load_single_rule(uc_rule);
                }
        }

        return num_rules_enabled;
}

static void
load_remote_settings(void)
{
        la_debug("load_remote_settings()");
        assert(la_config);

        la_config->remote_enabled = false;

        config_setting_t *remote_section =
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
        if (xstrlen(la_config->remote_secret) == 0)
                die_hard("Remote handling enabled but no secret specified");

        config_setting_t *receive_from = config_setting_lookup(remote_section,
                        LA_REMOTE_RECEIVE_FROM_LABEL);
        la_config->remote_receive_from = xcreate_list();
        compile_address_list(la_config->remote_receive_from, receive_from);

        la_config->remote_bind = xstrdup(config_get_string_or_null(remote_section,
                        LA_REMOTE_BIND_LABEL));

        la_config->remote_port = config_get_unsigned_int_or_negative(
                        remote_section, LA_REMOTE_PORT_LABEL);
        if (la_config->remote_port < 0)
                la_config->remote_port = DEFAULT_PORT;

        /* Must obviously go after initialization of remote port... */
        config_setting_t *send_to = config_setting_lookup(remote_section,
                        LA_REMOTE_SEND_TO_LABEL);
        la_config->remote_send_to = xcreate_list();
        compile_address_list_port(la_config->remote_send_to, send_to,
                        la_config->remote_port);

}

static void
load_defaults(void)
{
        la_debug("load_defaults()");
        assert(la_config);

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

                la_config->default_properties = xcreate_list();
                load_properties(la_config->default_properties, defaults_section);

                la_config->ignore_addresses = xcreate_list();
                config_setting_t *ignore = config_setting_get_member(
                                defaults_section, LA_IGNORE_LABEL);
                compile_address_list(la_config->ignore_addresses, ignore);
        }
        else
        {
                la_config->default_threshold = DEFAULT_THRESHOLD;
                la_config->default_period = DEFAULT_PERIOD;
                la_config->default_duration = DEFAULT_DURATION;
                la_config->default_meta_enabled = DEFAULT_META_ENABLED;
                la_config->default_meta_period = DEFAULT_META_PERIOD;
                la_config->default_meta_max = DEFAULT_META_MAX;
                la_config->default_properties = NULL;
                la_config->ignore_addresses = NULL;
        }
}

static const char ** include_func(config_t *config, const char *include_dir, const
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

bool
init_la_config(char *filename)
{
        if (!filename)
                filename = CONFIG_FILE;

        la_log(LOG_INFO, "Loading configuration from \"%s/%s\".", CONF_DIR,
                        filename);

        if (!la_config)
                la_config = xmalloc0(sizeof(la_config_t));

        config_init(&la_config->config_file);

        config_set_include_func(&la_config->config_file, include_func);

        if (!config_read_file(&la_config->config_file, filename))
        {
                const char *config_error_file =
                        config_error_file(&la_config->config_file);
                xpthread_mutex_unlock(&config_mutex);
                if (config_error_file)
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
        //init_config_mutex();

        xpthread_mutex_lock(&config_mutex);

        load_defaults();
        if (!load_rules())
        {
                xpthread_mutex_unlock(&config_mutex);
                die_hard("No rules enabledd!");
        }
        load_remote_settings();

        config_destroy(&la_config->config_file);

        xpthread_mutex_unlock(&config_mutex);
}

void
unload_la_config(void)
{
        la_debug("unload_la_config()");
        assert(la_config);

        /* In case shutdown is ongoing, don't bother with a mutex (which might
         * not have been correctly unlocked. OTOH, when reloading, it's
         * absolutely necessary to lock the mutex.
         */
        if (!shutdown_ongoing)
                xpthread_mutex_lock(&config_mutex);

        free_source_list(la_config->sources);
        la_config->sources = NULL;
#if HAVE_LIBSYSTEMD
        free_source(la_config->systemd_source);
        la_config->systemd_source = NULL;
#endif /* HAVE_LIBSYSTEMD */
        free_property_list(la_config->default_properties);
        la_config->default_properties = NULL;
        free_address_list(la_config->ignore_addresses);
        la_config->ignore_addresses = NULL;
        free(la_config->remote_secret);
        free_address_list(la_config->remote_receive_from);
        la_config->remote_receive_from = NULL;
        free_address_list(la_config->remote_send_to);
        la_config->remote_send_to = NULL;
        free(la_config->remote_bind);

        if (!shutdown_ongoing)
                xpthread_mutex_unlock(&config_mutex);
}

/*
 * Copied from example4.c from the libconfig distribution
 */

static const char **
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
                        strncat(include_path, include_dir, PATH_MAX);
                        include_path_len += xstrlen(include_dir);
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

                        /* TODO: error checking */
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
