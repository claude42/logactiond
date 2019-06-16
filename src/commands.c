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
#include <time.h>
#include <syslog.h>
#include <assert.h>
#include <limits.h>

#include <libconfig.h>

#include "logactiond.h"

void
assert_command_ffl(la_command_t *command, const char *func, char *file, unsigned int line)
{
        if (!command)
                die_hard("%s:%u: %s: Assertion 'command' failed. ", file, line, func);
        if (!command->name)
                die_hard("%s:%u: %s: Assertion 'command->name' failed.", file,
                                line, func);
        /* TODO: Not sure whether the next will break anything - let's see */
        if (!command->rule)
                die_hard("%s:%u: %s: Assertion 'command->rule' failed.", file,
                                line, func);
        if (!command->begin_string)
                die_hard("%s:%u: %s: Assertion 'command->begin_string' "
                                "failed.", file, line, func);
        assert_list_ffl(command->begin_properties, func, file, line);
        assert_list_ffl(command->end_properties, func, file, line);
}

/* Checks wether the specified property matches one of the special names and
 * returns the corresponding value if yes. Returns NULL otherwise
 *
 * - HOST
 * - RULE
 * - SOURCE
 * - IPVERSION
 */

static const char*
check_for_special_names(la_command_t *command, la_property_t *action_property)
{
        assert_command(command), assert_property(action_property);
        la_vdebug("check_for_special_names(%s)", action_property->name);

        if (command->address)
        {
                /* HOST */
                if (!strcmp(action_property->name, LA_HOST_TOKEN))
                        return command->address->text;

                /* IPVERSION */
                if (!strcmp(action_property->name, LA_IPVERSION_TOKEN))
                {
                        if (command->address->af == AF_INET)
                                return "4";
                        else if (command->address->af == AF_INET6)
                                return "6";
                        else
                                return "unknown";
                }
        }

        if (command->rule)
        {
                /* RULE */
                if (!strcmp(action_property->name, LA_RULENAME_TOKEN))
                        return command->rule->name;

                /* SOURCE */
                if (!strcmp(action_property->name, LA_SOURCENAME_TOKEN))
                        return command->rule->source->name;
        }

        return NULL;
}

/*
 * Returns the value of the specified property. Will look into
 *
 * - special property names (such as HOST, RULE, SOURCE, IPVERSION
 * - matched tokens in the pattern
 * - definitions in the config file rule section
 * - definitions in the config file default section
 *
 * Will return NULL if nothing is found.
 */

static const char *
get_value_for_action_property(la_command_t *command,
                la_property_t *action_property)
{
        assert_command(command); assert_property(action_property);
        la_vdebug("get_value_for_action_property(%s)", action_property->name);

        const char *result = NULL;

        /* try some standard names first */
        result = check_for_special_names(command, action_property);
        if (result)
                return result;

        /* next search among tokens from matched line */
        result = get_value_from_property_list(
                        command->pattern_properties,
                        action_property->name);
        if (result)
                return result;

        /* next search in config file rule section */
        if (command->rule)
        {
                result = get_value_from_property_list(command->rule->properties,
                                action_property->name);
                if (result)
                        return result;
        }

        /* lastly search in config file default section, return NULL if
         * nothing is there either */
        return get_value_from_property_list(la_config->default_properties,
                        action_property->name);
}

/*
 * Basically adds the length of all property values in begin_properties or
 * end_properties (depending on command type) to source_len.
 */

static size_t
compute_converted_length(la_command_t *command, la_commandtype_t type,
                size_t source_len)
{
        la_vdebug("compute_converted_length(%s)", command->name);

        size_t result = source_len;

        la_property_t  *action_property = ITERATE_PROPERTIES(
                        type == LA_COMMANDTYPE_BEGIN ?
                        command->begin_properties :
                        command->end_properties);

        while ((action_property = NEXT_PROPERTY(action_property)))
                result += xstrlen(get_value_for_action_property(command,
                                        action_property));

        return result;
}

static char *
convert_command(la_command_t *command, la_commandtype_t type)
{
        assert (command);
        la_debug("convert_command(%s, %s)", command->name,
                        type == LA_COMMANDTYPE_BEGIN ? "begin" : "end");

        const char *source_string = (type == LA_COMMANDTYPE_BEGIN) ?
                command->begin_string : command->end_string;
        const char *src_ptr = source_string;
        size_t dst_len = 2 * xstrlen(source_string);
        char *result = xmalloc(dst_len);
        char *dst_ptr = result;

        la_property_t *action_property = ITERATE_PROPERTIES(
                        type == LA_COMMANDTYPE_BEGIN ?
                        command->begin_properties :
                        command->end_properties);

        while (*src_ptr)
        {
                if (*src_ptr == '%')
                {
                        size_t length = token_length(src_ptr);
                        if (length > 2)
                        {
                                /* We've detected a token - not just "%%"
                                 */
                                action_property = NEXT_PROPERTY(action_property);
                                if (!action_property)
                                        die_hard("Ran out of properties?!?");
                                const char *repl =
                                        get_value_for_action_property(command,
                                                        action_property);
                                if (repl)
                                {
                                        /* Copy over value of action property
                                         * */
                                        size_t repl_len = xstrlen(repl);
                                        realloc_buffer(&result, &dst_ptr,
                                                        &dst_len, repl_len);
                                        dst_ptr = stpncpy(dst_ptr, repl, repl_len);
                                        src_ptr += length;
                                }
                                else
                                {
                                        /* in case there's no value found, we
                                         * now copy nothing - still TBD whether
                                         * this is a good idea */
                                        ;
                                }
                        }
                        else
                        {
                                /* In this case, we've only detected "%%", so
                                 * copy one % and skip the other one*/
                                realloc_buffer(&result, &dst_ptr, &dst_len, 1);
                                *dst_ptr++ = '%';
                                src_ptr += 2;
                        }
                }
                else if (*src_ptr == '\\')
                {
                        /* In case of '\', copy next character without any
                         * interpretation. */
                        realloc_buffer(&result, &dst_ptr, &dst_len, 2);
                        *dst_ptr++ = *src_ptr++;
                        *dst_ptr++ = *src_ptr++;
                }
                else
                {
                        /* simply copy all other characters */
                        realloc_buffer(&result, &dst_ptr, &dst_len, 1);
                        *dst_ptr++ = *src_ptr++;
                }
        }

        *dst_ptr = 0;
        la_vdebug("convert_command()=%s", result);

        return result;
}

/* TODO: refactor */
/*
 * 
 * TODO: current implementation leads to calling
 * get_value_for_action_property() twice per property which is unnecessarily
 * expensive. Let's find a better solution
 */

static char *
convert_command2(la_command_t *command, la_commandtype_t type)
{
        assert_command(command);

        const char *source_string = (type == LA_COMMANDTYPE_BEGIN) ?
                command->begin_string : command->end_string;
        la_debug("convert_command(%s, %s)", command->name,
                        type == LA_COMMANDTYPE_BEGIN ? "begin" : "end");

        size_t source_len = xstrlen(source_string);
        const char *string_ptr = source_string;

        char *result = xmalloc(compute_converted_length(command, type,
                                source_len));
        char *result_ptr = result;

        unsigned int start_pos = 0; /* position after last token */

        la_property_t *action_property = ITERATE_PROPERTIES(
                        type == LA_COMMANDTYPE_BEGIN ?
                        command->begin_properties :
                        command->end_properties);

        while ((action_property = NEXT_PROPERTY(action_property)))
        {
                /* copy string before next token */
                result_ptr = stpncpy(result_ptr, string_ptr, action_property->pos - start_pos);

                /* copy value for token */
                const char *repl = get_value_for_action_property(command,
                                action_property);
                if (repl)
                        result_ptr = stpncpy(result_ptr, repl, xstrlen(repl));
                else
                        /* in case there's no value found, we now copy nothing
                         * - still TBD whether this is a good idea */
                        ;


                start_pos = action_property->pos + action_property->length;
                string_ptr = source_string + start_pos;
        }

        /* Copy remainder of string - only if there's something left.
         * Double-check just to bes sure we don't overrun any buffer */
        if (string_ptr - source_string < source_len)
                /* strcpy() ok here because we definitley reserved enough space
                 */
                strcpy(result_ptr, string_ptr);
        else
                *result_ptr = '\0';

        la_vdebug("convert_command(%s)=%s", command->name, result);
        return result;
}

/*
 * Executes command string via system() and logs result.
 */

static void
exec_command(la_command_t *command, la_commandtype_t type)
{
        assert(command);
        la_debug("exec_command(%s)", command->name);

        int result = system(convert_command(command, type));
        switch (result)
        {
                case 0:
                        break;
                case -1:
                        la_log(LOG_ERR, "Could not create child process for "
                                        "action \"%s\".", command->name);
                        break;
                case 127:
                        la_log(LOG_ERR, "Could not execute shell for action "
                                        "\"%s\".", command->name);
                        break;
                default:
                        la_log(LOG_ERR, "Action \"%s\" returned with error "
                                        "code %d.", command->name, result);
                        break;
        }
}

/*
 * Executes a begin_command and enqueues an end_command into the queue (if one
 * hase been defined).
 */

void
trigger_command(la_command_t *command)
{
#ifndef NOCOMMANDS
        assert_command(command);
        la_debug("trigger_command(%s, %d)", command->name, command->duration);

        if (run_type == LA_UTIL_FOREGROUND)
                return;

        /* Don't trigger command if another command (no matter from which
         * template) is still active */
        if (command->address)
        {
                la_command_t *tmp = find_end_command(command->address);
                if (tmp)
                {
                                la_log(LOG_INFO, "Host: %s, ignored, action "
                                                "\"%s\" still " "active for "
                                                "rule \"%s\".",
                                                tmp->address->text, tmp->name,
                                                tmp->rule->name);
                                return;
                }
        }

        if (command->is_template)
                la_log(LOG_INFO, "Initializing action \"%s\" for rule \"%s\", "
                                "source \"%s\".", command->name,
                                command->rule->name,
                                command->rule->source->name);
        else
                la_log(LOG_INFO, "Host: %s, action \"%s\" fired for rule \"%s\".",
                                command->address->text, command->name,
                                command->rule->name);

        /* TODO: can't we convert_command() earlier? */
        exec_command(command, LA_COMMANDTYPE_BEGIN);

        if (command->end_string && command->duration > 0)
                enqueue_end_command(command);
        else
                free_command(command);
#endif /* NOCOMMANDS */
}

/*
 * Executes an end_command.
 *
 * Runs in end_queue_thread
 */

void
trigger_end_command(la_command_t *command)
{
        assert_command(command);
        la_vdebug("trigger_end_command(%s, %d)", command->name,
                        command->duration);

        if (command->duration == INT_MAX)
        {
                la_log(LOG_INFO, "Disabling rule \"%s\".",
                                command->rule->name);
        }
        else
        {
                if (command->address)
                        la_log(LOG_INFO, "Host: %s, action \"%s\" ended for "
                                        "rule \"%s\".",
                                        command->address->text, command->name,
                                        command->rule->name);
                else
                        la_log(LOG_INFO, "Action \"%s\" ended for rule "
                                        "\"%s\".", command->name,
                                        command->rule->name);
        }

        exec_command(command, LA_COMMANDTYPE_END);
}

/*
 * Scans pattern string for tokens. Adds found tokens to token_list.
 *
 * Return number of found tokens.
 */


static unsigned int
scan_action_tokens(kw_list_t *property_list, const char *string)
{
        assert_list(property_list); assert(string);
        la_debug("scan_action_tokens(%s)", string);

        const char *ptr = string;
        unsigned int n_tokens = 0;

        while (*ptr)
        {
                if (*ptr == '%')
                {
                        la_property_t *new_prop = scan_single_token(ptr,
                                        ptr-string, NULL);

                        if (new_prop)
                        {
                                add_tail(property_list, (kw_node_t *) new_prop);
                                n_tokens++;
                        }

                        ptr += xstrlen(new_prop->name) + 1;
                }

                ptr++; /* also skips over second '%' of a token */
        }

        return n_tokens;
}


/*
 * Clones command from a command template.
 * - Duplicates begin_properties / end_properties lists
 * - Doesn't clone begin_string, end_string, rule, pattern, host, end_time,
 *   n_triggers, start_time
 * Must be free()d after use.
 */

/* FIXME: when are we calling dup_command()? e.g. does the property list have
 * content ever? */

static la_command_t *
dup_command(la_command_t *command)
{
        assert_command(command);
        la_vdebug("dup_command(%s)", command->name);

        la_command_t *result = xmalloc(sizeof(la_command_t));

        result->id = command->id;

        result->is_template = false;

        result->name = command->name;
        result->begin_string = command->begin_string;
        result->begin_properties = dup_property_list(command->begin_properties);
        result->n_begin_properties = command->n_begin_properties;

        result->end_string = command->end_string;
        result->end_properties = dup_property_list(command->end_properties);
        result->n_end_properties = command->n_end_properties;

        result->duration = command->duration;
        result->need_host = command->need_host;

        return result;
}


/*
 * Create command from template. Duplicate template and add add'l information
 *
 * Returns NULL if if ip address does not match template->need_host setting.
 */

la_command_t *
create_command_from_template(la_command_t *template, la_rule_t *rule,
                la_pattern_t *pattern, la_address_t *address)
{
        assert_command(template); assert_rule(rule); assert_pattern(pattern);
        assert_list(pattern->properties);
        la_debug("create_command_from_template(%s)", template->name);

        /* Return if action can't handle type of IP address */
        if ((address->af == AF_INET && template->need_host ==
                                LA_NEED_HOST_IP6) ||
                        (address->af ==AF_INET6 && template->need_host ==
                         LA_NEED_HOST_IP4))
                return NULL;

        la_command_t *result = dup_command(template);

        result->rule = rule;
        result->pattern = pattern;
        result->pattern_properties = dup_property_list(pattern->properties);
        result->address = dup_address(address);
        result->end_time = result->n_triggers = result->start_time= 0;

        return result;
}

/*
 * Creates a new command template
 *
 * Duration = 0 prevents any end command
 * Duration = INT_MAX will result that the end command will only be fired on shutdown
 *
 * Note: begin_properties, end_properties will be initialized with
 * create_list(); pattern_properties will always be NULL after
 * create_template()
 *
 * FIXME: use another value than INT_MAX
 */

la_command_t *
create_template(const char *name, la_rule_t *rule, const char *begin_string,
                const char *end_string, unsigned int duration, la_need_host_t need_host)
{
        assert_rule(rule); assert(begin_string);
        la_debug("create_template(%s, %d)", name, duration);

        la_command_t *result = xmalloc(sizeof(la_command_t));

        result->name = xstrdup(name);
        result->id = ++id_counter;
        result->is_template = true;

        result->begin_string = xstrdup(begin_string);
        result->begin_properties = xcreate_list();
        result->n_begin_properties = begin_string ?
                scan_action_tokens(result->begin_properties, begin_string) : 0;

        result->end_string = xstrdup(end_string);
        result->end_properties = xcreate_list();
        result->n_end_properties = end_string ?
                scan_action_tokens(result->end_properties, end_string) : 0;

        result->rule = rule;
        result->pattern = NULL;
        result->pattern_properties = NULL;
        result->address = NULL;
        result->need_host = need_host;

        result->duration = duration;
        result->end_time = 0;

        result->n_triggers = 0;
        result->start_time = 0;

        assert_command(result);
        return result;
}

/*
 * Free single command. Does nothing when argument is NULL
 *
 * Runs in end_queue_thread
 */

void
free_command(la_command_t *command)
{
        if (!command)
                return;

        assert_command(command);
        la_vdebug("free_command(%s)", command->name);

        free_property_list(command->begin_properties);
        free_property_list(command->end_properties);
        free_property_list(command->pattern_properties);

        if (command->is_template)
        {
                free(command->name);
                free(command->begin_string);
                free(command->end_string);
        }

        free_address(command->address);
        free(command);
}

/*
 * Free all commands in list
 */

void
free_command_list(kw_list_t *list)
{
        la_vdebug("free_command_list()");
        if (!list)
                return;

        for (la_command_t *tmp;
                        (tmp = REM_COMMANDS_HEAD(list));)
                free_command(tmp);

        free(list);
}


/* vim: set autowrite expandtab: */
