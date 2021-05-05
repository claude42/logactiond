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
#include <stdbool.h>
#include <syslog.h>
#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <regex.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "ndebug.h"
#include "logactiond.h"
#include "addresses.h"
#include "commands.h"
#include "configfile.h"
#include "endqueue.h"
#include "logging.h"
#include "misc.h"
#include "patterns.h"
#include "properties.h"
#include "rules.h"
#include "sources.h"

void
assert_rule_ffl(const la_rule_t *rule, const char *func, const char *file, int line)
{
        if (!rule)
                die_hard(false, "%s:%u: %s: Assertion 'rule' failed. ", file,
                                line, func);
        if (!rule->node.nodename)
                die_hard(false, "%s:%u: %s: Assertion 'rule->name' failed. ",
                                file, line, func);
        if (strlen(rule->node.nodename) >= RULE_LENGTH)
                die_hard(false, "%s:%u: %s: Assertion 'strlen(rule->name) < "
                                "RULE_LENGTH' failed. ", file, line, func);

        assert_source_group_ffl(rule->source_group, func, file, line);
        assert_list_ffl(&rule->patterns, func, file, line);
        assert_list_ffl(&rule->begin_commands, func, file, line);
        if (rule->threshold < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule->threshold >= 0' "
                                "failed. ", file, line, func);
        if (rule->period < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule->period >= 0' "
                                "failed. ", file, line, func);
        if (rule->duration < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule->duration >= 0' "
                                "failed. ", file, line, func);
        if (rule->meta_period < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule->meta_period >= 0' "
                                "failed. ", file, line, func);
        if (rule->meta_max < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule->meta_max >= 0' "
                                "failed. ", file, line, func);
        assert_list_ffl(&rule->trigger_list, func, file, line);
        assert_list_ffl(&rule->properties, func, file, line);
        if (rule->detection_count < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule->detection_count "
                                ">= 0' failed. ", file, line, func);
        if (rule->invocation_count < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule->invocation_count "
                                ">= 0' failed. ", file, line, func);
        if (rule->queue_count < 0)
                die_hard(false, "%s:%u: %s: Assertion 'rule(%s)->queue_count >= 0' "
                                "failed. ", rule->node.nodename, file, line, func);
        assert_list_ffl(&rule->blacklists, func, file, line);
}

/*
 * Add command to trigger list of rule it belongs to.
 */

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
static void
add_trigger(la_command_t *command, time_t now)
{
        assert_command(command);
        la_debug_func(command->node.nodename);

        command->start_time = now;

        add_head(&command->rule->trigger_list, (kw_node_t *) command);
}

/*
 * Search for a command triggered by a certain host on the trigger_list of the
 * given rule. Return if found, return NULL otherwise.
 *
 * On the fly this also trims the trigger list from expired commands.
 */

static la_command_t *
find_trigger(const la_command_t *const template, const la_address_t *const address)
{
        assert_command(template);
        la_debug("find_trigger(%s, %u)", template->rule_name, template->id);

        if (!address)
                return NULL;
        assert_address(address);

        const time_t now = xtime(NULL);

        /* Don't use standard ITERATE_COMMANDS/NEXT_COMMAND idiom here to avoid
         * that remove_node() breaks the whole thing */
        la_command_t *command = ITERATE_COMMANDS(&template->rule->trigger_list);
        command = NEXT_COMMAND(command);
        while (command)
        {
                /* Return command if ids match */
                if (command->id == template->id &&
                                !adrcmp(command->address, address))
                        return command;

                la_command_t *const tmp = command;
                command = NEXT_COMMAND(command);
                /* Remove expired commands from trigger list */
                if (now - tmp->start_time > tmp->rule->period)
                {
                        /*la_log(LOG_INFO, "NOTE: Removed IP %s from \"%s\"",
                                        tmp->address->text, tmp->rule_name);*/
                        remove_node((kw_node_t *) tmp);
                        free_command(tmp);
                }
        }

        return NULL;
}

static void
update_n_triggers(la_command_t *const command)
{
        assert_command(command);
        la_vdebug_func(command->node.nodename);

        const time_t now = xtime(NULL);

        if (now - command->start_time > command->rule->period)
        {
                /* not within current period anymore - reset counter and period
                 */
                command->start_time = now;
                command->n_triggers = 0;
        }

        command->n_triggers++;
}

static void
trigger_then_enqueue_or_free(la_command_t *const command, const bool remove_command)
{
        if (remove_command)
                remove_node((kw_node_t *) command);
        trigger_command(command);
        if (command->end_string && command->duration > 0)
                enqueue_end_command(command, 0);
        else
                free_command(command);
}

/*
 * - Add command to trigger list if not in there yet.
 * - Increase counter by one.
 * - If counter > threshold, trigger command
 * - If period passed, reset counter
 */

static void
handle_command_on_trigger_list(la_command_t *const command)
{
        assert_command(command);
        la_debug_func(command->node.nodename);

        /* new commands not on the trigger_list yet have n_triggers == 0 */
        if (command->n_triggers == 0)
                add_trigger(command, xtime(NULL));

        update_n_triggers(command);

        assert_address(command->address);
        la_log(LOG_INFO, "Host: %s, trigger %u for rule \"%s\".",
                        command->address->text,
                        command->n_triggers,
                        command->rule_name);

        /* Trigger if > threshold */
        if (command->n_triggers >= command->rule->threshold)
                trigger_then_enqueue_or_free(command, true);
}

/*
 * Check whether address is on a dnsbl, if so trigger_command directly on first
 * sight. Only do dnsbl lookup if dnsbl_enabled==true and threshold>1
 */

static bool
trigger_if_on_dnsbl(la_command_t *command, bool from_trigger_list)
{
        assert_command(command);

        /* If threshold == 1 there's no point in doing the lookup... */
        if (!command->rule->dnsbl_enabled || command->rule->threshold == 1)
                return false;

        const char *const blname = command_address_on_dnsbl(command);
        if (!blname)
                return false;

        assert_address(command->address);
        la_log(LOG_INFO, "Host: %s blacklisted on %s.",
                        command->address->text, blname);

        command->previously_on_blacklist = true;
        trigger_then_enqueue_or_free(command, from_trigger_list);

        return true;
}

/*
 * Trigger command directly (in case threshold == 1 or no host identified) or
 * go via trigger list otherwise.
 *
 * Inputs
 * command - command to be triggered
 */

static void
trigger_single_command(la_pattern_t *const pattern,
                const la_address_t *const address,
                const la_command_t *const template)
{
        if  (run_type == LA_UTIL_FOREGROUND)
                return;

        assert_pattern(pattern); assert_command(template);
        la_debug_func(template->node.nodename);

        la_command_t *command = NULL;

        if (address)
        {
                assert_address(address);
                /* First check whether a command for this host is still active
                 * on end_queue. In this case, ignore new command */
                command = find_end_command(address);
                if (command)
                        LOG_RETURN_VERBOSE(, LOG_INFO, "Host: %s, ignored, "
                                        "action \"%s\" already active "
                                        "(triggered by rule \"%s\").",
                                        address->text, command->node.nodename,
                                        command->rule_name);

                /* Check whether the same command has been triggered (but not yet
                 * fired) by the same host before.
                 */
                command = find_trigger(template, address);
        }
        else if (template->need_host != LA_NEED_HOST_NO)
        {
                /* Don't trigger command if need_host==true but no host
                 * property exists */
                LOG_RETURN(, LOG_ERR, "Missing required host token, action "
                                "\"%s\" not fired for rule \"%s\"!",
                                template->node.nodename,
                                pattern->rule->node.nodename);
        }

        const bool from_trigger_list = command;

        if (!from_trigger_list)
        {
                 /* Create new command if not found. If host is not set, always
                  * create new command.
                 */
                command = create_command_from_template(template, pattern,
                                address);
                if (!command)
                        LOG_RETURN(, LOG_ERR, "IP address doesn't match "
                                        "requirements of action!");
        }

        /* Trigger directly if found on DNSBL, otherwise handle via trigger
         * list */
        if (!trigger_if_on_dnsbl(command, from_trigger_list))
                handle_command_on_trigger_list(command);
}
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */

/*
 * Increases pattern->detection_count and pattern->rule_detection_count by 1.
 */

static void
increase_detection_count(la_pattern_t *const pattern)
{
        assert_pattern(pattern);
        la_vdebug_func(NULL);

        if (pattern->detection_count < LONG_MAX)
                pattern->detection_count++;
        if (pattern->rule->detection_count < LONG_MAX)
                pattern->rule->detection_count++;
}

/*
 * Trigger all commands assigned to a rule
 *
 * Inputs
 * pattern - pattern that matched
 */

static void
trigger_all_commands(la_pattern_t *const pattern)
{
        assert_pattern(pattern);
        la_debug("trigger_all_commands(%s, %s)", pattern->rule->node.nodename, pattern->string);

        const char *host = NULL;
        la_address_t address = { 0 };
        if (pattern->host_property)
        {
                host = pattern->host_property->value;
                /* in case IP address cannot be converted, ignore trigger
                 * altogether */
                if (!init_address(&address, host))
                        LOG_RETURN(, LOG_ERR, "Invalid IP address \"%s\", trigger "
                                        "ignored!", host);

                /* Do nothing if on ignore list */
                assert(la_config);
                la_address_t *tmp_addr = address_on_list(&address, &la_config->ignore_addresses);
                if (tmp_addr)
                {
                        reprioritize_node((kw_node_t *) tmp_addr, 1);
                        LOG_RETURN_VERBOSE(, LOG_INFO,
                                        "Host: %s, always ignored.",
                                        tmp_addr->domainname ? tmp_addr->domainname :
                                        tmp_addr->text);
                }
        }

        increase_detection_count(pattern);
#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
        /* trigger all of rule's commands */
        for (la_command_t *template =
                        ITERATE_COMMANDS(&pattern->rule->begin_commands);
                        (template = NEXT_COMMAND(template));)
                trigger_single_command(pattern, host ? &address : NULL, template);
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
}


#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
void
trigger_manual_commands_for_rule(const la_address_t *const address,
                const  la_rule_t *const rule, const time_t end_time,
                const int factor, const la_address_t *const from_addr,
                const bool suppress_logging)
{
        la_debug_func(NULL);
        assert_address(address); assert_rule(rule);

        for (la_command_t *template = ITERATE_COMMANDS(&rule->begin_commands);
                        (template = NEXT_COMMAND(template));)
                trigger_manual_command(address, template, end_time, factor,
                                from_addr, suppress_logging);
}
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */

/*
 * Assign values to existing properties from matched pattern
 *
 * Inputs
 * property_list - existing properties from pattern
 * line - matched log line
 * pmatch - result from regexec() call pointing to matches in line
 */

static bool
assign_value_to_properties(const kw_list_t *const property_list,
                const char *const line, regmatch_t pmatch[])
{
        assert_list(property_list); assert(line);
        la_vdebug_func(NULL);

        for (la_property_t *property = ITERATE_PROPERTIES(property_list);
                        (property = NEXT_PROPERTY(property));)
        {
                if (!string_copy(property->value, MAX_PROP_SIZE,
                                        line + pmatch[property->subexpression].rm_so,
                                        pmatch[property->subexpression].rm_eo -
                                        pmatch[property->subexpression].rm_so, '\0'))
                        return false;
        }

        return true;
}

/*
 * Clear value of all properties in list
 */

static void
clear_property_values(const kw_list_t *const property_list)
{
        assert_list(property_list);
        la_vdebug_func(NULL);

        for (la_property_t *property = ITERATE_PROPERTIES(property_list);
                        (property = NEXT_PROPERTY(property));)
                property->value[0] = '\0';
}

/*
 * Matches line to all patterns assigned to rule. Does regexec() with all
 * patterns. Does trigger_all_commands() for those that match.
 */

bool
handle_log_line_for_rule(const la_rule_t *const rule, const char *const line)
{
        assert_rule(rule); assert(line);
        la_vdebug("handle_log_line_for_rule(%s, %s)", rule->node.nodename, line);

        for (la_pattern_t *pattern = ITERATE_PATTERNS(&rule->patterns);
                        (pattern = NEXT_PATTERN(pattern));)
        {
                /* TODO: make this dynamic based on detected tokens */
                regmatch_t pmatch[MAX_NMATCH];
                if (!regexec(&(pattern->regex), line, MAX_NMATCH, pmatch, 0))
                {
                        /* TODO: maybe better to make a copy of peroprty list
                         * first and assign values to this list so these don't
                         * have to be cleared afterwards */
                        if (assign_value_to_properties(&pattern->properties,
                                                line, pmatch))
                                trigger_all_commands(pattern);
                        else
                                la_log(LOG_ERR, "Matched property too long, "
                                                "log line ignored");
                        clear_property_values(&pattern->properties);

                        reprioritize_node((kw_node_t *) pattern, 1);
                        return true;
                }
        }

        return false;
}

/*
 * Create a new rule
 *
 * Inputs
 * source - source file this rule applies to
 * threshold - how many time a rule must match in the given period before an
 * command is triggered
 * period - period (in seconds) for the threshold
 * duration - duration (in seconds) after which end command is activated
 *
 * Returns
 * Created rule. Does patterns, begin_commands, trigger_lit, properties with
 * empty lists but does not add any elements.
 */

la_rule_t *
create_rule(const bool enabled, const char *const name,
                la_source_group_t *const source_group, const int threshold,
                const int period, const int duration, const int dnsbl_duration,
                const int meta_enabled, const int meta_period,
                const int meta_factor, const int meta_max,
                const int dnsbl_enabled, const char *service,
                const char *systemd_unit)
{
        assert_source_group(source_group);
        la_debug_func(name);

        if (!name)
                die_hard(false, "No rule name specified!");
        if (strchr(name, ','))
                die_hard(false, "Rule name may not contain a ','!");
        if (strlen(name) >= RULE_LENGTH)
                die_hard(false, "Rulename too long - must be less than %u "
                                "characters!", RULE_LENGTH);

        la_rule_t *const result = create_node(sizeof *result, 0, name);

        result->enabled = enabled;

        result->id = ++id_counter;
        result->source_group = source_group;

        if (threshold >= 0)
                result->threshold = threshold;
        else if (la_config->default_threshold >= 0)
                result->threshold = la_config->default_threshold;
        else
                result->threshold = 1;

        result->duration = duration!=-1 ? duration : la_config->default_duration;
        result->dnsbl_duration = dnsbl_duration!=-1 ? dnsbl_duration :
                la_config->default_dnsbl_duration;
        result->period = period!=-1 ? period : la_config->default_period;

        result->meta_enabled = meta_enabled>=0 ? meta_enabled :
                la_config->default_meta_enabled;

        result->meta_period = meta_period!=-1 ? meta_period : la_config->default_meta_period;
        result->meta_factor = meta_factor!=-1 ? meta_factor : la_config->default_meta_factor;
        result->meta_max = meta_max!=-1 ? meta_max : la_config->default_meta_max;

        result->dnsbl_enabled = dnsbl_enabled;

        result->service = xstrdup(service);
#if HAVE_LIBSYSTEMD
        result->systemd_unit = xstrdup(systemd_unit);
#else /* HAVE_LIBSYSTEMD */
        result->systemd_unit = NULL;
#endif /* HAVE_LIBSYSTEMD */

        init_list(&result->patterns);
        init_list(&result->begin_commands);
        init_list(&result->trigger_list);
        init_list(&result->properties);
        init_list(&result->blacklists);

        result->detection_count = result->invocation_count =
                result->queue_count = 0;

        assert_rule(result);
        return result;
}

/*
 * Free single rule. Does nothing when argument is NULL
 */

void
free_rule(la_rule_t *const rule)
{
        if (!rule)
                return;

        la_vdebug_func(rule->node.nodename);

#if HAVE_LIBSYSTEMD
        free(rule->systemd_unit);
#endif /* HAVE_LISTSYSTEMD */
        free(rule->service);

        empty_pattern_list(&rule->patterns);
        empty_command_list(&rule->begin_commands);
        empty_command_list(&rule->trigger_list);
        empty_property_list(&rule->properties);
        empty_list(&rule->blacklists, NULL);

        free(rule->node.nodename);

        free(rule);
}


static la_rule_t *
find_rule_for_source_group(const la_source_group_t *const source_group,
                const char *const rule_name)
{
        assert_source_group(source_group); assert(rule_name);
        la_debug_func(rule_name);

        for (la_rule_t *result = ITERATE_RULES(&source_group->rules);
                        (result = NEXT_RULE(result));)
        {
                if (!strcmp(rule_name, result->node.nodename))
                        return result;
        }

        return NULL;
}

la_rule_t *
find_rule(const char *const rule_name)
{
        assert(rule_name); assert(la_config);
        la_debug_func(rule_name);

#if HAVE_LIBSYSTEMD
        if (la_config->systemd_source_group)
        {
                la_rule_t *const result = find_rule_for_source_group(
                                la_config->systemd_source_group, rule_name);
                if (result)
                        return result;
        }
#endif /* HAVE_LIBSYSTEMD */

        assert_list(&la_config->source_groups);
        for (la_source_group_t *source_group = ITERATE_SOURCE_GROUPS(&la_config->source_groups);
                        (source_group = NEXT_SOURCE_GROUP(source_group));)
        {
                la_rule_t *const result = find_rule_for_source_group(source_group, rule_name);
                if (result)
                        return result;
        }

        return NULL;
}

/* vim: set autowrite expandtab: */
