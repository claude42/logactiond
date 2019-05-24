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
#include <stdbool.h>
#include <syslog.h>
#include <assert.h>
#include <limits.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

/* FIXME: trigger_list should definitely be a hash */

void
assert_rule_ffl(la_rule_t *rule, const char *func, char *file, unsigned int line)
{
        if (!rule)
                die_hard("%s:%u: %s: Assertion 'rule' failed. ", file, line, func);
        if (!rule->name)
                die_hard("%s:%u: %s: Assertion 'rule->name' failed. ", file, line, func);
        if (!rule->source)
                assert_source_ffl(rule->source, func, file, line);
        assert_list_ffl(rule->patterns, func, file, line);
        assert_list_ffl(rule->begin_commands, func, file, line);
        assert_list_ffl(rule->trigger_list, func, file, line);
        assert_list_ffl(rule->properties, func, file, line);
}

/*
 * Add command to trigger list of rule it belongs to.
 */

static void
add_trigger(la_command_t *command)
{
        assert_command(command);
        la_debug("add_trigger(%s)", command->name);

        command->n_triggers = 0;
        command->start_time = xtime(NULL);

        add_head(command->rule->trigger_list, (kw_node_t *) command);

        assert_list(command->rule->trigger_list);
}

/*
 * Search for a command triggered by a certain host on the trigger_list of the
 * given rule. Return if found, return NULL otherwise.
 */

static la_command_t *
find_trigger(la_rule_t *rule, la_command_t *template, la_address_t *address)
{
        assert_rule(rule); assert_command(template);
        la_debug("find_trigger(%s, %u)", rule->name, template->id);

        if (!address)
                return NULL;

        for (la_command_t *command = ITERATE_COMMANDS(rule->trigger_list);
                        (command = NEXT_COMMAND(command));)
        {
                if (command->id == template->id &&
                                !adrcmp(command->address, address))
                        return command;
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
                        if (command->rule->invocation_count < ULONG_MAX)
                                command->rule->invocation_count++;
                        trigger_command(command);
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
trigger_single_command(la_rule_t *rule, la_pattern_t *pattern,
                la_address_t *address, la_command_t *template)
{
#ifndef NOCOMMANDS
        if  (run_type == LA_UTIL_FOREGROUND)
                return;

        assert_rule(rule); assert_pattern(pattern);
        assert_command(template);
        la_debug("trigger_single_command(%s)", template->name);

        la_command_t *command = NULL;

        /* First check whether command still active on end_queue. In this
         * case, ignore new command */
        la_command_t *tmp = find_end_command(rule, address);
        if (tmp)
        {
                if (address)
                        la_log(LOG_INFO, "Host: %s, ignored, action \"%s\" still "
                                        "active for rule \"%s\".", address->text,
                                        tmp->name, rule->name);
                else
                        la_log(LOG_INFO, "Ignored, action \"%s\" still active "
                                        "for rule \"%s\".", tmp->name,
                                        rule->name);
                return;
        }

        /* Check whether the same command has been triggered (but not yet
         * fired) by the same host before. Create new command if not found. If
         * host is not set, always create new command.
         */
        command = find_trigger(rule, template, address);

        if (!command)
        {
                /* Don't trigger command if need_host=true but not host
                 * property exists */
                if (template->need_host != LA_NEED_HOST_NO &&
                                !address)
                {
                        la_log(LOG_ERR, "Missing required host token, action "
                                        "\"%s\" not fired for rule \"%s\"!",
                                        command->name,
                                        command->rule->name);
                        return;
                }
                command = create_command_from_template(template, rule,
                                pattern, address);
                if (!command)
                {
                        la_debug("IP doesn't match what action can do");
                        return;
                }
        }

        handle_command_on_trigger_list(command);
#endif /* NOCOMMANDS */
}

/*
 * Trigger all commands assigned to a rule
 *
 * Inputs
 * rule - 
 * pattern - pattern that matched
 */

static void
trigger_all_commands(la_rule_t *rule, la_pattern_t *pattern)
{
        assert_rule(rule); assert_pattern(pattern);
        la_debug("trigger_all_commands(%s)", rule->name);

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
        if (address_on_ignore_list(address))
        {
                la_log(LOG_INFO, "Host: %s, always ignored.", host);
        }
        else
        {
                for (la_command_t *template =
                                ITERATE_COMMANDS(rule->begin_commands);
                                (template = NEXT_COMMAND(template));)
                        trigger_single_command(rule, pattern, address, template);
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
assign_value_to_properties(kw_list_t *property_list, char *line,
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
handle_log_line_for_rule(la_rule_t *rule, char *line)
{
        assert_rule(rule); assert(line);
        la_vdebug("handle_log_line_for_rule(%s)", rule->name);

        unsigned int count = 0;
        for (la_pattern_t *pattern = ITERATE_PATTERNS(rule->patterns);
                        (pattern = NEXT_PATTERN(pattern));)
        {
                /* TODO: make this dynamic based on detected tokens */
                regmatch_t pmatch[MAX_NMATCH];
                if (!regexec(pattern->regex, line, MAX_NMATCH, pmatch, 0))
                {
                        if (pattern->detection_count < ULONG_MAX)
                                pattern->detection_count++;
                        if (pattern->rule->detection_count < ULONG_MAX)
                                pattern->rule->detection_count++;
                        assign_value_to_properties(pattern->properties, line,
                                        pmatch);
                        trigger_all_commands(rule, pattern);
                        clear_property_values(pattern->properties);
                        return;
                }
                count++;
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
                int duration, const char *service)
{
        assert_source(source);
        la_debug("create_rule(%s)", name);

        la_rule_t *result = xmalloc(sizeof(la_rule_t));

        result->name = xstrdup(name);
        result->source = source;

        if (threshold >= 0)
                result->threshold = threshold;
        else if (la_config->default_threshold >= 0)
                result->threshold = la_config->default_threshold;
        else
                result->threshold = 1;

        result->duration = duration!=-1 ? duration : la_config->default_duration;
        result->period = period!=-1 ? period : la_config->default_period;

        result->service = xstrdup(service);

        result->patterns = create_list();
        result->begin_commands = create_list();
        result->trigger_list = create_list();
        result->properties = create_list();

        result->detection_count = result->invocation_count = 0;

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

        assert_rule(rule);
        la_vdebug("free_rule(%s)", rule->name);

        free(rule->service);

        free_pattern_list(rule->patterns);
        free_command_list(rule->begin_commands);
        free_command_list(rule->trigger_list);
        free_property_list(rule->properties);

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

        for (la_rule_t *tmp;
                        (tmp = REM_RULES_HEAD(list));)
                free_rule(tmp);

        free(list);
}



/* vim: set autowrite expandtab: */
