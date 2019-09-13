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
#include <syslog.h>
#include <assert.h>
#include <limits.h>
#include <sys/socket.h>

#include <libconfig.h>

#include "logactiond.h"


#define ITERATE_META_COMMANDS(COMMANDS) (meta_command_t *) &(COMMANDS)->head
#define NEXT_META_COMMAND(COMMAND) (meta_command_t *) (COMMAND->node.succ->succ ? COMMAND->node.succ : NULL)
#define HAS_NEXT_META_COMMAND(COMMAND) COMMAND->node.succ
#define REM_META_COMMANDS_HEAD(COMMANDS) (meta_command_t *) rem_head(COMMANDS)

typedef struct la_meta_command_s
{
        kw_node_t node;
        la_rule_t *rule;
        la_address_t *address;
        unsigned int meta_n_triggers;
        time_t meta_start_time;
} meta_command_t;

void
assert_command_ffl(la_command_t *command, const char *func, char *file, unsigned int line)
{
        if (!command)
                die_hard("%s:%u: %s: Assertion 'command' failed. ", file, line, func);
        if (!command->name)
                die_hard("%s:%u: %s: Assertion 'command->name' failed.", file,
                                line, func);
        assert_rule_ffl(command->rule, func, file, line);
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

        /* RULE */
        if (!strcmp(action_property->name, LA_RULENAME_TOKEN))
                return command->rule->name;

        /* SOURCE */
        if (!strcmp(action_property->name, LA_SOURCENAME_TOKEN))
                return command->rule->source->name;

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
        result = get_value_from_property_list(command->rule->properties,
                        action_property->name);
        if (result)
                return result;

        /* lastly search in config file default section, return NULL if
         * nothing is there either */
        return get_value_from_property_list(la_config->default_properties,
                        action_property->name);
}

static char *
convert_command(la_command_t *command, la_commandtype_t type)
{
        /* Don't assert_command() here, as after a reload some commands might
         * not have a rule attached to them anymore */
        assert(command); assert(command->name); assert(command->end_string);
        assert((type == LA_COMMANDTYPE_BEGIN && command->begin_properties &&
                                command->begin_string) ||
                        (type == LA_COMMANDTYPE_END && command->end_properties &&
                         command->end_properties));
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
                                }
                                else
                                {
                                        /* in case there's no value found, we
                                         * now copy nothing - still TBD whether
                                         * this is a good idea */
                                        ;
                                }
                                src_ptr += length;
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
        la_debug("convert_command()=%s", result);

        return result;
}


/*
 * Executes command string via system() and logs result.
 */

static void
exec_command(la_command_t *command, la_commandtype_t type)
{
        /* Don't assert_command() here, as after a reload some commands might
         * not have a rule attached to them anymore */
        assert(command);
        assert(command->name);
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
 * Tries to find a command on the meta list which
 * a.) has last been invoked within the meta_period
 * b.) has the same address as the given command
 *
 * On the fly this also trims the meta list from expired commands.
 */

#ifndef NOCOMMANDS
static void
free_meta_command(meta_command_t *meta_command)
{
        la_debug("free_meta_command()");
        assert(meta_command);

        free_address(meta_command->address);
        free(meta_command);
}

void
free_meta_command_list(kw_list_t *list)
{
        la_vdebug("free_meta_command_list()");
        if (!list)
                return;
        assert_list(list);

        for (meta_command_t *tmp;
                        (tmp = REM_META_COMMANDS_HEAD(list));)
                free_meta_command(tmp);

        free(list);
}

static meta_command_t *
create_meta_command(la_command_t *command)
{
        meta_command_t *result = xmalloc(sizeof(meta_command_t));

        result->rule = command->rule;
        result->address = dup_address(command->address);
        result->meta_start_time = xtime(NULL);
        result->meta_n_triggers = 1;

        return result;
}

static meta_command_t *
find_on_meta_list(la_command_t *command)
{
        assert_command(command);
        la_debug("find_on_meta_list(%s)", command->name);

        time_t now = xtime(NULL);

        /* Don't use standard ITERATE_COMMANDS/NEXT_COMMAND idiom here to avoid
         * that remove_node() breaks the whole thing */
        assert(la_config); assert_list(la_config->meta_list);
        meta_command_t *list_command = ITERATE_META_COMMANDS(la_config->meta_list);
        list_command = NEXT_META_COMMAND(list_command);
        while (list_command)
        {
                if (now - list_command->rule->meta_period)
                {
                        if (!adrcmp(command->address, list_command->address))
                                return list_command;
                        list_command = NEXT_META_COMMAND(list_command);
                }
                else
                {
                        /* Remove expired commands from trigger list */
                        meta_command_t *tmp = list_command;
                        list_command = NEXT_META_COMMAND(list_command);
                        remove_node((kw_node_t *) tmp);
                        free_meta_command(tmp);
                }
        }

        return NULL;
}

/*
 * Checks whether a coresponding command is already on the meta_list (see
 * find_on_meta_list(). If so, increases trigger counter. Returns true if >
 * threshold.
 *
 * If nothings found on the list, clone command and add to the list.
 */

static bool
check_meta_list(la_command_t *command)
{
        assert_command(command);
        la_debug("check_meta_list(%s, %u)", command->address->text,
                        command->duration);

        meta_command_t *meta_command = find_on_meta_list(command);

        if (meta_command)
        {
                if (++meta_command->meta_n_triggers >= 
                                meta_command->rule->meta_threshold)
                {
                        remove_node((kw_node_t *) meta_command);
                        free_meta_command(meta_command);
                        return true;
                }
                else
                {
                        return false;
                }

        }
        else
        {
                meta_command = create_meta_command(command);
                add_head(la_config->meta_list, (kw_node_t *) meta_command);
                return false;
        }
}

static void
incr_invocation_counts(la_command_t *command)
{
        assert_command(command);
        if (command->rule->invocation_count < ULONG_MAX)
                command->rule->invocation_count++;
        if (command->pattern->invocation_count < ULONG_MAX)
                command->pattern->invocation_count++;
}

/*
 * Executes a begin_command and enqueues an end_command into the queue (if one
 * hase been defined).
 */

void
trigger_command(la_command_t *command)
{
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
                        la_log(LOG_INFO, "Host: %s, ignored, action \"%s\" "
                                        "already active (triggered by rule "
                                        "\"%s\").",
                                        tmp->address->text, tmp->name,
                                        tmp->rule->name);
                        return;
                }
        }

        if (command->is_template)
        {
                la_debug("Initializing action \"%s\" for rule \"%s\", "
                                "source \"%s\".", command->name,
                                command->rule->name,
                                command->rule->source->name);
        }
        else
        {
                /* handle meta list, check if meta_duration should be used */
                bool meta = false;
                if (command->rule->meta_enabled && check_meta_list(command))
                {
                        command->duration = command->rule->meta_duration;
                        meta = true;
                }

                la_log(LOG_INFO, "Host: %s, %saction \"%s\" activated by rule \"%s\".",
                                command->address->text, meta ? "META " : "",
                                command->name, command->rule->name);

                /* update relevant counters for status monitoring */
                incr_invocation_counts(command);
                command->rule->queue_count++;
        }

        exec_command(command, LA_COMMANDTYPE_BEGIN);

        if (command->end_string && command->duration > 0)
                enqueue_end_command(command);
        else
                free_command(command);
}
#endif /* NOCOMMANDS */

/*
 * Executes an end_command.
 *
 * Runs in end_queue_thread
 */

void
trigger_end_command(la_command_t *command)
{
        /* Don't assert_command() here, as after a reload some commands might
         * not have a rule attached to them anymore */
        assert(command);
        la_vdebug("trigger_end_command(%s, %d)", command->name,
                        command->duration);

        if (command->is_template)
        {
                la_log(LOG_INFO, "Disabling rule \"%s\".",
                                command->rule->name);
        }
        else
        {
                if (command->address)
                        la_log(LOG_INFO, "Host: %s, action \"%s\" ended for "
                                        "rule \"%s\".", command->address->text,
                                        command->name, command->rule_name);
                else
                        la_log(LOG_INFO, "Action \"%s\" ended for rule "
                                        "\"%s\".", command->name,
                                        command->rule_name);

                /* After a reload some commands might not have a rule attached
                 * to them anymore */
                if (command->rule)
                        command->rule->queue_count--;
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
 * Clones command from a command template. Duplicates / copies most but not all
 * template parameters. dup_command() should only be called from
 * create_command_from_template().
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

        result->name = xstrdup(command->name);
        result->begin_string = xstrdup(command->begin_string);
        result->begin_properties = dup_property_list(command->begin_properties);
        result->n_begin_properties = command->n_begin_properties;

        result->end_string = xstrdup(command->end_string);
        result->end_properties = dup_property_list(command->end_properties);
        result->n_end_properties = command->n_end_properties;

        result->rule = command->rule;

        result->duration = command->duration;
        result->need_host = command->need_host;

        result->rule_name = xstrdup(command->rule_name);

        return result;
}


/*
 * Create command from template. Duplicate template and add add'l information
 *
 * Returns NULL if ip address does not match template->need_host setting.
 */

la_command_t *
create_command_from_template(la_command_t *template, la_pattern_t *pattern,
                la_address_t *address)
{
        assert_command(template); assert_pattern(pattern);
        assert_list(pattern->properties);
        la_debug("create_command_from_template(%s)", template->name);

        /* Return if action can't handle type of IP address */

        if (!address)
        {
                if (template->need_host != LA_NEED_HOST_NO)
                        return NULL;
        }
        else
        {
                if ((address->af == AF_INET && template->need_host ==
                                        LA_NEED_HOST_IP6) ||
                                (address->af == AF_INET6 &&
                                                template->need_host ==
                                                LA_NEED_HOST_IP4))
                        return NULL;
        }

        la_command_t *result = dup_command(template);

        result->pattern = pattern;
        result->pattern_properties = dup_property_list(pattern->properties);
        result->address = address ? dup_address(address) : NULL;
        result->end_time = result->n_triggers = result->start_time= 0;

        assert_command(result);
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
        assert(name); assert_rule(rule); assert(begin_string);
        la_debug("create_template(%s, %d)", name, duration);

        la_command_t *result = xmalloc(sizeof(la_command_t));

        result->name = xstrdup(name);
        result->id = ++id_counter;
        result->is_template = true;

        result->begin_string = xstrdup(begin_string);
        result->begin_properties = xcreate_list();
        result->n_begin_properties =
                scan_action_tokens(result->begin_properties, begin_string);

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

        /* Will be used to restore queue counters on reload. Yes, it's a bit
         * ugly but such is life... */
        result->rule_name = xstrdup(rule->name);

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

        free(command->name);
        free(command->begin_string);
        free(command->end_string);
        free_property_list(command->begin_properties);
        free_property_list(command->end_properties);
        free_property_list(command->pattern_properties);
        free(command->rule_name);

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
        assert_list(list);

        for (la_command_t *tmp;
                        (tmp = REM_COMMANDS_HEAD(list));)
                free_command(tmp);

        free(list);
}


/* vim: set autowrite expandtab: */
