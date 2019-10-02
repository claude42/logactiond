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
#include <stdbool.h>
#include <syslog.h>
#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <regex.h>
#include <string.h>

#include "logactiond.h"

/* FIXME: trigger_list should definitely be a hash */

void
assert_rule_ffl(la_rule_t *rule, const char *func, char *file, unsigned int line)
{
        if (!rule)
                die_hard("%s:%u: %s: Assertion 'rule' failed. ", file, line, func);
        if (!rule->name)
                die_hard("%s:%u: %s: Assertion 'rule->name' failed. ", file, line, func);
        assert_source_ffl(rule->source, func, file, line);
        assert_list_ffl(rule->patterns, func, file, line);
        assert_list_ffl(rule->begin_commands, func, file, line);
        assert_list_ffl(rule->trigger_list, func, file, line);
        assert_list_ffl(rule->properties, func, file, line);
}

/*
 * Add command to trigger list of rule it belongs to.
 */

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
static void
add_trigger(la_command_t *command)
{
        assert_command(command);
        la_debug("add_trigger(%s)", command->name);

        command->start_time = xtime(NULL);

        add_head(command->rule->trigger_list, (kw_node_t *) command);

        assert_list(command->rule->trigger_list);
}

/*
 * Search for a command triggered by a certain host on the trigger_list of the
 * given rule. Return if found, return NULL otherwise.
 *
 * On the fly this also trims the trigger list from expired commands.
 */

static la_command_t *
find_trigger(la_command_t *template, la_address_t *address)
{
        assert_command(template);
        la_debug("find_trigger(%s, %u)", template->rule->name, template->id);

        if (!address)
                return NULL;

        time_t now = xtime(NULL);

        /* Don't use standard ITERATE_COMMANDS/NEXT_COMMAND idiom here to avoid
         * that remove_node() breaks the whole thing */
        la_command_t *command = ITERATE_COMMANDS(template->rule->trigger_list);
        command = NEXT_COMMAND(command);
        while (command)
        {
                /* Return command if ids match */
                if (command->id == template->id &&
                                !adrcmp(command->address, address))
                        return command;

                la_command_t *tmp = command;
                command = NEXT_COMMAND(command);
                /* Remove expired commands from trigger list */
                if (now - tmp->start_time > tmp->rule->period)
                {
                        /*la_log(LOG_INFO, "NOTE: Removed IP %s from \"%s\"",
                                        tmp->address->text, tmp->rule->name);*/
                        remove_node((kw_node_t *) tmp);
                }
        }

        return NULL;
}

/*
 * - Add command to trigger list if not in there yet.
 * - Increase counter by one.
 * - If counter > threshold, trigger command
 * - If period passed, reset counter
 */

static void
handle_command_on_trigger_list(la_command_t *command)
{
        assert_command(command);
        la_debug("handle_command_on_trigger_list(%s)", command->name);

        /* new commands not on the trigger_list yet have n_triggers == 0 */
        if (command->n_triggers == 0)
                add_trigger(command);

        /* Go through this also for newly added commands - in case threshold = 1 */
        if (xtime(NULL) - command->start_time < command->rule->period)
        {
                /* still within current period - increase counter,
                 * trigger if necessary */
                command->n_triggers++;
                la_log(LOG_INFO, "Host: %s, trigger %u for rule \"%s\".",
                                command->address->text,
                                command->n_triggers,
                                command->rule->name);
                if (command->n_triggers >= command->rule->threshold)
                {
                        remove_node((kw_node_t *) command);
                        trigger_command(command);
                        if (command->end_string && command->duration > 0)
                                enqueue_end_command(command);
                        else
                                free_command(command);
                }
        }
        else
        {
                /* if not, reset counter and period */
                command->start_time = xtime(NULL);
                command->n_triggers = 1;
                la_log(LOG_INFO, "Host: %s, trigger 1 for rule \"%s\".",
                                command->address->text,
                                command->rule->name);
        }
}

/*
 * Trigger command directly (in case threshold == 1 or no host identified) or
 * go via trigger list otherwise.
 *
 * Inputs
 * command - command to be triggered
 */

static void
trigger_single_command(la_pattern_t *pattern, la_address_t *address,
                la_command_t *template)
{
        if  (run_type == LA_UTIL_FOREGROUND)
                return;

        assert_pattern(pattern); assert_rule(pattern->rule);
        assert_command(template);
        la_debug("trigger_single_command(%s)", template->name);

        la_command_t *command = NULL;

        /* First check whether a command for this host is still active on
         * end_queue. In this case, ignore new command */
        la_command_t *tmp = find_end_command(address);
        if (tmp)
        {
                la_log_verbose(LOG_INFO, "Host: %s, ignored, action \"%s\" "
                                "already active (triggered by rule \"%s\").",
                                address->text, tmp->name, tmp->rule->name);
                return;
        }

        /* Check whether the same command has been triggered (but not yet
         * fired) by the same host before. Create new command if not found. If
         * host is not set, always create new command.
         */
        command = find_trigger(template, address);

        bool from_trigger_list;
        if (command)
        {
                from_trigger_list = true;
        }
        else
        {
                /* Don't trigger command if need_host==true but no host
                 * property exists */
                if (template->need_host != LA_NEED_HOST_NO &&
                                !address)
                {
                        la_log(LOG_ERR, "Missing required host token, action "
                                        "\"%s\" not fired for rule \"%s\"!",
                                        template->name,
                                        pattern->rule->name);
                        return;
                }
                command = create_command_from_template(template, pattern,
                                address);
                if (!command)
                {
                        la_log(LOG_ERR, "IP address doesn't match what requirements of action!");
                        return;
                }
                from_trigger_list = false;
        }

        /* Check whether address is on a dnsbl, if so trigger_command directly
         * on first sight. Only do dnsbl lookup if dnsbl_enabled==true and
         * threshold>1 */

        if  (pattern->rule->dnsbl_enabled && pattern->rule->threshold > 1)
        {
                for (kw_node_t *bl = &pattern->rule->blacklists->head;
                                (bl = bl->succ->succ ? bl->succ : NULL);) {
                        if (host_on_dnsbl(address, bl->name))
                        {
                                la_log(LOG_INFO, "Host: %s blacklisted on %s.",
                                                address->text, bl->name);
                                if (from_trigger_list)
                                        remove_node((kw_node_t *) command);
                                trigger_command(command);
                                if (command->end_string && command->duration > 0)
                                        enqueue_end_command(command);
                                return;
                        }
                }
        }

        handle_command_on_trigger_list(command);
}
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */

/*
 * Increases pattern->detection_count and pattern->rule_detection_count by 1.
 */

static void
increase_detection_count(la_pattern_t *pattern)
{
        assert_pattern(pattern);
        la_vdebug("increase_detection_count()");

        if (pattern->detection_count < ULONG_MAX)
                pattern->detection_count++;
        if (pattern->rule->detection_count < ULONG_MAX)
                pattern->rule->detection_count++;
}

/*
 * Trigger all commands assigned to a rule
 *
 * Inputs
 * rule - 
 * pattern - pattern that matched
 */

static void
trigger_all_commands(la_pattern_t *pattern)
{
        assert_pattern(pattern); assert_rule(pattern->rule);
        la_debug("trigger_all_commands(%s)", pattern->rule->name);

        const char *host = get_host_property_value(pattern->properties);

        la_address_t *address = NULL;
        if (host)
        {
                address = create_address(host);
                /* in case IP address cannot be converted, ignore trigger
                 * altogether */
                if (!address)
                {
                        la_log(LOG_ERR, "Invalid IP address \"%s\", trigger "
                                        "ignored!", host);
                        return;
                }
        }

        /* Do nothing if on ignore list */
        assert(la_config);
        if (address_on_list(address, la_config->ignore_addresses))
        {
                la_log_verbose(LOG_INFO, "Host: %s, always ignored.", host);
        }
        else
        {
                increase_detection_count(pattern);
#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)
                for (la_command_t *template =
                                ITERATE_COMMANDS(pattern->rule->begin_commands);
                                (template = NEXT_COMMAND(template));)
                        trigger_single_command(pattern, address, template);
#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */
        }

        free_address(address);
}

/*
 * Assign values to existing properties from matched pattern
 *
 * Inputs
 * property_list - existing properties from pattern
 * line - matched log line
 * pmatch - result from regexec() call pointing to matches in line
 */

static void
assign_value_to_properties(kw_list_t *property_list, const char *line,
                regmatch_t pmatch[])
{
        assert_list(property_list); assert(line);
        la_debug("assign_value_to_properties()");

        for (la_property_t *property = ITERATE_PROPERTIES(property_list);
                        (property = NEXT_PROPERTY(property));)
        {
                property->value = xstrndup(line + pmatch[property->subexpression].rm_so,
                                pmatch[property->subexpression].rm_eo -
                                pmatch[property->subexpression].rm_so);
        }
}

/*
 * Clear value of all properties in list
 */

static void
clear_property_values(kw_list_t *property_list)
{
        assert_list(property_list);
        la_debug("clear_property_values()");

        for (la_property_t *property = ITERATE_PROPERTIES(property_list);
                        (property = NEXT_PROPERTY(property));)
        {
                free(property->value);
                property->value = NULL;
        }
}

/*
 * Matches line to all patterns assigned to rule. Does regexec() with all
 * patterns. Does trigger_all_commands() for those that match.
 */

void
handle_log_line_for_rule(la_rule_t *rule, const char *line)
{
        assert_rule(rule); assert(line);
        la_vdebug("handle_log_line_for_rule(%s)", rule->name);

        for (la_pattern_t *pattern = ITERATE_PATTERNS(rule->patterns);
                        (pattern = NEXT_PATTERN(pattern));)
        {
                /* TODO: make this dynamic based on detected tokens */
                regmatch_t pmatch[MAX_NMATCH];
                if (!regexec(pattern->regex, line, MAX_NMATCH, pmatch, 0))
                {
                        assign_value_to_properties(pattern->properties, line,
                                        pmatch);
                        trigger_all_commands(pattern);
                        clear_property_values(pattern->properties);
                        return;
                }
        }
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
create_rule(char *name, la_source_t *source, int threshold, int period,
                int duration, int meta_enabled, int meta_period,
                int meta_factor, int meta_max, int dnsbl_enabled, const char
                *service, const char *systemd_unit)
{
        assert_source(source);
        la_debug("create_rule(%s)", name);

        la_rule_t *result = xmalloc(sizeof(la_rule_t));

        result->name = xstrdup(name);
        result->id = ++id_counter;
        result->source = source;

        if (threshold >= 0)
                result->threshold = threshold;
        else if (la_config->default_threshold >= 0)
                result->threshold = la_config->default_threshold;
        else
                result->threshold = 1;

        result->duration = duration!=-1 ? duration : la_config->default_duration;
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

        result->patterns = xcreate_list();
        result->begin_commands = xcreate_list();
        result->trigger_list = xcreate_list();
        result->properties = xcreate_list();
        result->blacklists = xcreate_list();

        result->detection_count = result->invocation_count =
                result->queue_count = 0;

        assert_rule(result);
        return result;
}

/*
 * Free single rule. Does nothing when argument is NULL
 */

void
free_rule(la_rule_t *rule)
{
        if (!rule)
                return;

        la_vdebug("free_rule(%s)", rule->name);

#if HAVE_LIBSYSTEMD
        free(rule->systemd_unit);
#endif /* HAVE_LISTSYSTEMD */
        free(rule->service);

        free_pattern_list(rule->patterns);
        free_command_list(rule->begin_commands);
        free_command_list(rule->trigger_list);
        free_property_list(rule->properties);
        for (kw_node_t *node; ((node = rem_head(rule->blacklists)));)
        {
                free(node->name);
                free(node);
        }

        free(rule->name);

        free(rule);
}

/*
 * Free all rules in list
 */

void
free_rule_list(kw_list_t *list)
{
        la_vdebug("free_rule_list()");

        if (!list)
                return;
        assert_list(list);

        for (la_rule_t *tmp;
                        (tmp = REM_RULES_HEAD(list));)
                free_rule(tmp);

        free(list);
}


static la_rule_t *
find_rule_for_source(la_source_t *source, char *rule_name)
{
        assert_source(source); assert(rule_name);
        la_debug("find_rule_for_source(%s)", rule_name);

        for (la_rule_t *result = ITERATE_RULES(source->rules);
                        (result = NEXT_RULE(result));)
        {
                if (!strcmp(rule_name, result->name))
                        return result;
        }

        return NULL;
}

la_rule_t *
find_rule(char *rule_name)
{
        assert(rule_name); assert(la_config);
        la_debug("find_rule(%s)", rule_name);

        la_rule_t *result;
#if HAVE_LIBSYSTEMD
        if (la_config->systemd_source)
        {
                result = find_rule_for_source(la_config->systemd_source,
                                rule_name);
                if (result)
                        return result;
        }
#endif /* HAVE_LIBSYSTEMD */

        assert_list(la_config->sources);
        for (la_source_t *source = ITERATE_SOURCES(la_config->sources);
                        (source = NEXT_SOURCE(source));)
        {
                result = find_rule_for_source(source, rule_name);
                if (result)
                        return result;
        }

        return NULL;
}

/* vim: set autowrite expandtab: */
