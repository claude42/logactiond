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

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

/* FIXME: trigger_list should definitely be a hash */

void
assert_rule(la_rule_t *rule)
{
        assert(rule);
        assert(rule->name);
        assert(rule->source);
        assert_list(rule->patterns);
        assert_list(rule->begin_commands);
        assert_list(rule->trigger_list);
        assert_list(rule->properties);
}


/*
 * Iterates through all compiled regexs for one rule.
 */

static inline kw_node_t*
get_pattern_iterator_for_rule(la_rule_t *rule)
{
	return get_list_iterator(rule->patterns);
}

static inline la_pattern_t *
get_next_pattern_for_rule(kw_node_t **iterator)
{
	return (la_pattern_t *) get_next_node(iterator);
}

/*
 * Remove command from triggr list
 */

/*
 * Add command to trigger list of rule it belongs to.
 */

static void
add_trigger(la_command_t *command)
{
        assert_command(command);

        la_debug("add_trigger(%s)\n", command->begin_string);

	command->n_triggers = 0;
	command->start_time = time(NULL);

	add_head(command->rule->trigger_list, (kw_node_t *) command);

        assert_list(command->rule->trigger_list);
}

/*
 * Search for a command triggered by a certain host on the trigger_list of the
 * given rule. Return if found, return NULL otherwise.
 */

static la_command_t *
find_trigger(la_rule_t *rule, const char *command_string, const char *host)
{
        assert_rule(rule); assert(command_string); assert(host);

	if (!host || !command_string)
		die_hard("No host / command_string specified\n");

        la_debug("find_trigger(%s, %s, %s)\n", rule->name, command_string, host);

	for (la_command_t *command = (la_command_t *) rule->trigger_list->head.succ;
			command->node.succ;
			command = (la_command_t *) command->node.succ)
	{
		if (command->host)
		{
			/* TODO: two strcmps are definitely inefficient */
                        if (!strcmp(command->begin_string, command_string) &&
					!strcmp(command->host, host))
				return command;
		}
	}

	return NULL;
}

/* TODO: definitely should refactor */

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

        la_debug("handle_command_on_trigger_list(%s)\n", command->begin_string);

	/* new commands not on the trigger_list yet have n_triggers == 0 */
	if (command->n_triggers == 0)
		add_trigger(command);

        if (time(NULL) - command->start_time < command->rule->period)
        {
                /* still within current period - increase counter,
                 * trigger if necessary */
                command->n_triggers++;
                la_log(LOG_INFO, "Host: %s, trigger %u for rule %s\n",
                                command->host,
                                command->n_triggers,
                                command->rule->name);
                if (command->n_triggers >= command->rule->threshold)
                {
                        remove_node((kw_node_t *) command);
                        la_log(LOG_INFO, "Host: %s, command fired for rule %s\n",
                                command->host,
                                command->rule->name);
                        trigger_command(command);
                }
        }
        else
        {
                /* if not, reset counter and period */
                command->start_time = time(NULL);
                command->n_triggers = 1;
                la_log(LOG_INFO, "Host: %s, trigger 1 for rule %s\n",
                                command->host,
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
                const char *host, la_command_t *template)
{
        assert_rule(rule); assert_pattern(pattern); assert(host);
        assert_command(template);

        la_debug("trigger_single_command(%s)\n", template->begin_string);

        la_command_t *command = NULL;

        /* First check whether command still active on end_queue. In this
         * case, ignore new command */
        if (find_end_command(rule, host))
        {
                la_log(LOG_INFO, "Host: %s ignored, command active for %s\n",
                                        host, rule->name);
                return;
        }

        /* Check whether the same command has been triggered (but not yet
         * fired) by the same host before. Create new command if not found. If
         * host is not set, always create new command.
         */
        // TODO: maybe add "need_host" config parameter. Don't trigger command
        // at all w/o host in this case
        if (host)
                command = find_trigger(rule, template->begin_string, host);

        if (!command)
                command = create_command_from_template(template, rule, pattern, host);

        handle_command_on_trigger_list(command);
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

	la_debug("trigger_all_commands()\n");

        const char *host = get_host_property_value(pattern->properties);

        /* Do nothing if on ignore list */
        if (address_on_ignore_list(host))
        {
                la_log(LOG_INFO, "Host: %s, always ignored\n", host);
                return;
        }

        for (la_command_t *template = (la_command_t *) rule->begin_commands->head.succ;
                        template->node.succ;
                        template = (la_command_t *) template->node.succ)
	{
                trigger_single_command(rule, pattern, host, template);
	}
}

/*
 * Assign values to existing properties from matched pattern
 *
 * Inputs
 * property_list - existing properties from pattern
 * line - matched log line
 * pmatch - result from regexec() call pointing to matches in line
 *
 * FIXME: will not work with multiple threads
 */

static void
assign_value_to_properties(kw_list_t *property_list, const char *line,
		regmatch_t pmatch[])
{
        assert_list(property_list); assert(line);

        la_debug("assign_value_to_properties()\n");

	for (la_property_t *property = (la_property_t *) property_list->head.succ;
			property->node.succ;
			property = (la_property_t *) property->node.succ)
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
        assert(property_list);

        la_debug("clear_property_values()\n");

        for (la_property_t *property = (la_property_t *) property_list->head.succ;
                        property->node.succ;
                        property = (la_property_t *) property->node.succ)
        {
                if (property->value)
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

        la_debug("handle_log_line()\n");

	kw_node_t *i = get_pattern_iterator_for_rule(rule);
	la_pattern_t *pattern;

	while ((pattern = get_next_pattern_for_rule(&i)))
	{
		/* TODO: make this dynamic based on detected tokens */
		regmatch_t pmatch[MAX_NMATCH];
		if (!regexec(pattern->regex, line, MAX_NMATCH, pmatch, 0))
		{
			assign_value_to_properties(pattern->properties, line,
					pmatch);
			trigger_all_commands(rule, pattern);
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
create_rule(char *name, la_source_t *source, int threshold, int period, int
		duration)
{
	la_rule_t *result = (la_rule_t *) xmalloc(sizeof(la_rule_t));

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

	result->patterns = create_list();
	result->begin_commands = create_list();
	result->trigger_list = create_list();
        result->properties = create_list();

	return result;
}


/* vim: set autowrite expandtab: */
