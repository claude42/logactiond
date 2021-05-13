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

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
/* keep these 3 in, even if deheader says to remote them. Necessary e.g. for
 * FreeBSD */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "ndebug.h"
#include "addresses.h"
#include "commands.h"
#include "configfile.h"
#include "endqueue.h"
#include "logactiond.h"
#include "misc.h"
#include "fifo.h"
#include "logging.h"
#include "patterns.h"
#include "properties.h"
#include "remote.h"
#include "rules.h"
#include "sources.h"
#include "binarytree.h"
#include "dnsbl.h"
#include "fifo.h"
#include "metacommands.h"
#include "nodelist.h"

void
assert_command_ffl(const la_command_t *command, const char *func,
                const char *file, int line)
{
        if (!command)
                die_hard(false, "%s:%u: %s: Assertion 'command' failed. ",
                                file, line, func);
        if (!command->node.nodename)
                die_hard(false, "%s:%u: %s: Assertion 'command->name' failed.",
                                file, line, func);

        assert_list_ffl(&command->begin_properties, func, file, line);
        if (command->n_begin_properties < 0)
                die_hard(false, "%s:%u: %s: Assertion 'command->n_begin_properties "
                                ">= 0' failed. ", file, line, func);
        if (command->n_begin_properties != list_length(&command->begin_properties))
                die_hard(false, "%s:%u: %s: Assertion 'command->n_begin_properties "
                                "== list_length(&command->begin_properties failed.",
                                file, line, func);

        assert_list_ffl(&command->end_properties, func, file, line );
        if (command->n_end_properties < 0)
                die_hard(false, "%s:%u: %s: Assertion 'command->n_end_properties "
                                ">= 0' failed. ", file, line, func);
        if (command->n_end_properties != list_length(&command->end_properties))
                die_hard(false, "%s:%u: %s: Assertion 'command->n_end_properties "
                                "== list_length(command->end_properties failed.",
                                file, line, func);

        assert_rule_ffl(command->rule, func, file, line);
        if (command->pattern)
                assert_pattern_ffl(command->pattern, func, file, line);
        if (command->pattern_properties.head.succ)
                assert_list_ffl(&command->pattern_properties, func, file, line);
        if (command->address)
                assert_address_ffl(command->address, func, file, line);

        if (command->factor < -1)
                die_hard(false, "%s:%u: %s: Assertion 'command->factor >= 0' "
                                "failed.", file, line, func);

        if (command->n_triggers < 0)
                die_hard(false, "%s:%u: %s: Assertion 'command->n_n_triggers "
                                ">= 0' failed.", file, line, func);

        if (!command->begin_string)
                die_hard(false, "%s:%u: %s: Assertion 'command->begin_string' "
                                "failed.", file, line, func);



        assert_list_ffl(&command->begin_properties, func, file, line);
        assert_list_ffl(&command->end_properties, func, file, line);

        if (command->duration < -1)
                die_hard(false, "%s:%u: %s: Assertion 'command->duration >= -1' "
                                "failed. ", file, line, func);

        if (strcmp(command->rule->node.nodename, command->rule_name))
                die_hard(false, "%s:%u: %s: Assertion 'strcmp(command->rule->name, "
                                "command->rule_name)' failed. ", file, line,
                                func);


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
check_for_special_names(const la_command_t *const command, const la_property_t *const action_property)
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
                        return get_ip_version(command->address);
        }

        /* RULE */
        if (!strcmp(action_property->name, LA_RULENAME_TOKEN))
                return command->rule_name;

        /* SOURCE */
        if (!strcmp(action_property->name, LA_SOURCENAME_TOKEN))
                return command->rule->source_group->node.nodename;

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
get_value_for_action_property(const la_command_t *const command,
                const la_property_t *const action_property)
{
        assert_command(command); assert_property(action_property);
        la_vdebug("get_value_for_action_property(%s)", action_property->name);

        /* try some standard names first */
        const char *result = check_for_special_names(command, action_property);
        if (result)
                return result;

        /* next search among tokens from matched line */
        result = get_value_from_property_list(
                        &command->pattern_properties,
                        action_property->name);
        if (result)
                return result;

        /* next search in config file rule section */
        result = get_value_from_property_list(&command->rule->properties,
                        action_property->name);
        if (result)
                return result;

        /* lastly search in config file default section, return NULL if
         * nothing is there either */
        return get_value_from_property_list(&la_config->default_properties,
                        action_property->name);
}

/* Convert command->begin_string / end_string (depending on command type. I.e.
 * replace any %SOMETHING% with the corresponding property value.
 */

static void
convert_command(la_command_t *const command, const la_commandtype_t type)
{
        assert_command(command);
        assert(type == LA_COMMANDTYPE_BEGIN || type == LA_COMMANDTYPE_END);
        la_debug("convert_command(%s, %s)", command->node.nodename,
                        type == LA_COMMANDTYPE_BEGIN ? "begin" : "end");

        if (!((type == LA_COMMANDTYPE_BEGIN &&
                                        !is_list_empty(&command->begin_properties) &&
                                        command->begin_string) ||
                        (type == LA_COMMANDTYPE_END &&
                                         !is_list_empty(&command->end_properties) &&
                                         command->end_string)))
                return;

        const char *const source_string = (type == LA_COMMANDTYPE_BEGIN) ?
                command->begin_string : command->end_string;
        const char *src_ptr = source_string;
        size_t dst_len = 2 * xstrlen(source_string);
        char *result = xmalloc(dst_len);
        char *dst_ptr = result;

        la_property_t *action_property = ITERATE_PROPERTIES(
                        type == LA_COMMANDTYPE_BEGIN ?
                        &command->begin_properties :
                        &command->end_properties);

        while (*src_ptr)
        {
                switch (*src_ptr)
                {
                case '%':
                        if (src_ptr[1] != '%')
                        {
                                /* We've detected a token - not just "%%"
                                 */
                                action_property = NEXT_PROPERTY(action_property);
                                if (!action_property)
                                        die_hard(false, "Ran out of "
                                                        "properties?!?");
                                const char *const repl =
                                        get_value_for_action_property(command,
                                                        action_property);
                                if (repl)
                                {
                                        /* Copy over value of action property
                                         * */
                                        const size_t repl_len = xstrlen(repl);
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
                                src_ptr += token_length(src_ptr);
                        }
                        else
                        {
                                /* In this case, we've only detected "%%", so
                                 * copy one % and skip the other one*/
                                realloc_buffer(&result, &dst_ptr, &dst_len, 1);
                                *dst_ptr++ = '%';
                                src_ptr += 2;
                        }
                        break;
                case '\\':
                        /* In case of '\', copy next character without any
                         * interpretation. */
                        realloc_buffer(&result, &dst_ptr, &dst_len, 2);
                        *dst_ptr++ = *src_ptr++;
                        *dst_ptr++ = *src_ptr++;
                        break;
                default:
                        /* simply copy all other characters */
                        realloc_buffer(&result, &dst_ptr, &dst_len, 1);
                        *dst_ptr++ = *src_ptr++;
                        break;
                }
        }

        *dst_ptr = 0;
        la_debug("convert_command()=%s", result);

        if (type == LA_COMMANDTYPE_BEGIN)
                command->begin_string_converted = result;
        else
                command->end_string_converted = result;
}

void
convert_both_commands(la_command_t *const command)
{
        convert_command(command, LA_COMMANDTYPE_BEGIN);
        convert_command(command, LA_COMMANDTYPE_END);
}


/*
 * Executes command string via system() and logs result.
 */

void
exec_command(const la_command_t *command, const la_commandtype_t type)
{
        /* Don't assert_command() here, as after a reload some commands might
         * not have a rule attached to them anymore */
        assert(command);
        assert(command->node.nodename);
        la_debug_func(command->node.nodename);

        const int result = system(type == LA_COMMANDTYPE_BEGIN ?
                        command->begin_string_converted :
                        command->end_string_converted);
        switch (result)
        {
        case 0:
                break;
        case -1:
                la_log(LOG_ERR, "Could not create child process for "
                                "action \"%s\".", command->node.nodename);
                break;
        case 127:
                la_log(LOG_ERR, "Could not execute shell for action "
                                "\"%s\". Error code %d.",
                                command->node.nodename, WEXITSTATUS(result));
                break;
        default:
                la_log(LOG_ERR, "Action \"%s\" returned with error "
                                "code %d.", command->node.nodename, WEXITSTATUS(result));
                la_log(LOG_ERR, "Tried to execute \"%s\"",
                                type == LA_COMMANDTYPE_BEGIN ?
                                command->begin_string_converted :
                                command->end_string_converted);
                break;
        }
}

#if !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS)

static void
incr_invocation_counts(la_command_t *const command)
{
        assert_command(command);
        if (command->rule->invocation_count < LONG_MAX)
                command->rule->invocation_count++;
        if (command->pattern->invocation_count < LONG_MAX)
                command->pattern->invocation_count++;

        command->rule->queue_count++;
}

static void
log_trigger(const la_command_t *const command, const la_address_t *const from_addr)
{

        if (from_addr)
        {
                /* manual command */
                if (command->factor)
                        la_log(LOG_INFO, "Host: %s, action \"%s\" activated "
                                        "by host %s, rule \"%s\" (factor %d).",
                                        command->address->text, command->node.nodename,
                                        ADDRESS_NAME(from_addr),
                                        command->rule_name,
                                        command->factor);
                else
                        la_log(LOG_INFO, "Host: %s, action \"%s\" activated "
                                        "by host %s, rule \"%s\".",
                                        command->address->text, command->node.nodename,
                                        ADDRESS_NAME(from_addr),
                                        command->rule_name);
        }
        else if (command->is_template)
        {
                /* template */
                la_log_verbose(LOG_INFO, "Initializing action \"%s\" for "
                                "rule \"%s\", source \"%s\".", command->node.nodename,
                                command->rule_name,
                                command->rule->source_group->node.nodename);
        }
        else if (!command->address)
        {
                /* command without associated address */
                la_log(LOG_INFO, "Action \"%s\" activated by rule \"%s\".",
                                command->node.nodename, command->rule_name);
        }
        else if (command->rule->meta_enabled)
        {
                /* command with factor */
                la_log(LOG_INFO, "Host: %s, action \"%s\" activated "
                                "by rule \"%s\" (factor %d).",
                                command->address->text, command->node.nodename,
                                command->rule_name, command->factor);
        }
        else
        {
                /* command w/o factor */
                la_log(LOG_INFO, "Host: %s, action \"%s\" activated "
                                "by rule \"%s\".",
                                command->address->text, command->node.nodename,
                                command->rule_name);
        }
}


/*
 * Executes a command submitted manually or from a remote logactiond
 */

void
trigger_manual_command(const la_address_t *const address,
                const la_command_t *const template, const time_t end_time,
                const int factor, const la_address_t *const from_addr,
                const bool suppress_logging)
{
        assert_address(address); assert_command(template);
        la_debug_func(NULL);

        /* If end_time was specified, check whether it's already in the past.
         * If so, do nothing */
        if (end_time && xtime(NULL) > end_time)
                LOG_RETURN_VERBOSE(, LOG_INFO, "Manual command ignored as end time "
                                "is in the past.");

        assert(la_config);
        la_address_t *tmp_addr = address_on_list(address, &la_config->ignore_addresses);
        if (tmp_addr)
        {
                reprioritize_node((kw_node_t *) tmp_addr, 1);
                LOG_RETURN(, LOG_INFO, "Host: %s, manual trigger ignored.",
                                ADDRESS_NAME(tmp_addr));
        }

        const la_command_t *const tmp_cmd = find_end_command(address);
        if (tmp_cmd)
                LOG_RETURN_VERBOSE(, LOG_INFO, "Host: %s, ignored, action \"%s\" "
                                "%s%s already "
                                "active (triggered by rule \"%s\").",
                                address->text, tmp_cmd->node.nodename, 
                                from_addr ? "by host " : "",
                                from_addr ? from_addr->text : "",
                                tmp_cmd->rule_name);

        la_command_t *const command = create_manual_command_from_template(template, 
                        address, from_addr);
        if (!command)
                LOG_RETURN(, LOG_ERR, "IP address doesn't match what requirements of action!");
        assert_command(command);

        if (command->rule->meta_enabled)
                command->factor = check_meta_list(command, factor);
        else
                command->factor = 0;

        if (!suppress_logging || log_verbose)
                log_trigger(command, from_addr);

        command->rule->queue_count++;

        exec_command(command, LA_COMMANDTYPE_BEGIN);
        if (command->end_string && command->duration > 0)
        {
                /* If end_time was specified, use this. Otherwise  (i.e. if
                 * end_time is 0), end_time will becomputed based on duration
                 * and factor */
                enqueue_end_command(command, end_time);
        }
        else
        {
                free_command(command);
        }
}

/*
 * Executes a begin_command.
 */

void
trigger_command(la_command_t *const command)
{
        assert_command(command);
        la_debug("trigger_command(%s, %d)", command->node.nodename, command->duration);

        if (run_type == LA_UTIL_FOREGROUND)
                return;

        if (!command->is_template)
        {
                if (command->rule->meta_enabled)
                        command->factor = check_meta_list(command, 0);

                /* update relevant counters for status monitoring */
                incr_invocation_counts(command);

                send_add_entry_message(command, NULL);
        }

        log_trigger(command, NULL);

        exec_command(command, LA_COMMANDTYPE_BEGIN);
}

#endif /* !defined(NOCOMMANDS) && !defined(ONLYCLEANUPCOMMANDS) */

static void
log_end_trigger(const la_command_t *const command)
{
        if (command->is_template)
                la_log(LOG_INFO, "Disabling rule \"%s\".", command->rule_name);
        else if (command->address)
                la_log(LOG_INFO, "Host: %s, action \"%s\" ended for "
                                "rule \"%s\".", command->address->text,
                                command->node.nodename, command->rule_name);
        else
                la_log(LOG_INFO, "Action \"%s\" ended for rule " "\"%s\".",
                                command->node.nodename, command->rule_name);
}

/*
 * Executes an end_command.
 *
 * Will suppress any logging, if suppress_logging is true (main use case: avoid
 * 100s of log lines on shutdown. Will still log in case started with -v.
 *
 * Runs in end_queue_thread
 */

void
trigger_end_command(const la_command_t *const command, const bool suppress_logging)
{
        /* Don't assert_command() here, as after a reload some commands might
         * not have a rule attached to them anymore */
        assert(command);
        la_vdebug("trigger_end_command(%s, %d)", command->node.nodename,
                        command->duration);

        /* condition used to be (!suppress_logging || log_verbose) but that was
         * still too verbose... */
        if (log_verbose)
                log_end_trigger(command);

        /* After a reload some commands might not have a rule attached
         * to them anymore */
        if (!command->is_template && command->rule)
                command->rule->queue_count--;

        exec_command(command, LA_COMMANDTYPE_END);
}

/*
 * Scans pattern string for tokens. Adds found tokens to token_list.
 *
 * Return number of found tokens.
 */


static int
scan_action_tokens(kw_list_t *const property_list, const char *const string)
{
        assert(string);
        la_debug_func(string);

        assert(property_list);
        init_list(property_list);

        const char *ptr = string;
        int n_tokens = 0;

        while (*ptr)
        {
                if (*ptr == '%')
                {
                        la_property_t *const new_prop = create_property_from_token(
                                        ptr, ptr-string, NULL);

                        if (new_prop)
                        {
                                add_tail(property_list, (kw_node_t *) new_prop);
                                n_tokens++;
                                ptr += new_prop->length-2; /* two %s reflected later */
                        }

                        ptr++; /* account for first '%' of token */
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
dup_command(const la_command_t *const command)
{
        assert_command(command);
        la_vdebug("dup_command(%s)", command->node.nodename);

        la_command_t *const result = create_node0(sizeof *result, 0, command->node.nodename);

        result->id = command->id;

        result->is_template = false;

        /* only set payload here, other node links have already been
         * initialized in template */
        result->adr_node.payload = result;

        result->begin_string = xstrdup(command->begin_string);
        init_list(&result->begin_properties);
        copy_property_list(&result->begin_properties, &command->begin_properties);
        result->n_begin_properties = command->n_begin_properties;

        result->end_string = xstrdup(command->end_string);
        init_list(&result->end_properties);
        copy_property_list(&result->end_properties, &command->end_properties);
        result->n_end_properties = command->n_end_properties;

        result->rule = command->rule;

        result->duration = command->duration;
        result->factor = command->factor;
        result->need_host = command->need_host;
        result->quick_shutdown = command->quick_shutdown;

        result->rule_name = xstrdup(command->rule_name);

        return result;
}

/* Return false if action can't handle type of IP address */

static bool
has_correct_address(const la_command_t *const template, const la_address_t *const address)
{
        assert_command(template);

        if (!address && template->need_host != LA_NEED_HOST_NO)
                return false;
        else if (template->need_host == LA_NEED_HOST_IP4 && address->sa.ss_family != AF_INET)
                return false;
        else if (template->need_host == LA_NEED_HOST_IP6 && address->sa.ss_family != AF_INET6)
                return false;
        else if (template->need_host == LA_NEED_HOST_ANY && address->sa.ss_family != AF_INET
                        && address->sa.ss_family != AF_INET6)
                return false;
        else
                return true;
}

/*
 * Create command from template. Duplicate template and add add'l information
 *
 * Returns NULL if ip address does not match template->need_host setting.
 */

la_command_t *
create_command_from_template(const la_command_t *const template,
                la_pattern_t *const pattern,
                const la_address_t *const address)
{
        assert_command(template); assert_pattern(pattern);
        assert_list(&pattern->properties);
        if (address)
                assert_address(address);
        la_debug_func(template->node.nodename);

        if (!has_correct_address(template, address))
                return NULL;

        la_command_t *const result = dup_command(template);

        result->pattern = pattern;
        init_list(&result->pattern_properties);
        copy_property_list(&result->pattern_properties, &pattern->properties);

        result->address = address ? dup_address(address) : NULL;
        result->end_time = result->n_triggers = result->start_time= 0;
        result->submission_type = LA_SUBMISSION_LOCAL;
        result->previously_on_blacklist = false;

        convert_both_commands(result);

        return result;
}

/*
 * TODO: recognize access from other local addresses
 */

#ifndef CLIENTONLY
static
bool is_local_address(const la_address_t *const address)
{
        return (!address || address == &fifo_address ||
                        !strcmp("127.0.0.1", address->text) ||
                        !strcmp("::1", address->text));
}
#endif /* CLIENTONLY */

/* TODO: combine both create*command*() methods into one */

la_command_t *
create_manual_command_from_template(const la_command_t *const template,
                const la_address_t *const address, const la_address_t *const from_addr)
{
        assert_command(template);
        if (address)
                assert_address(address);
        la_debug_func(template->node.nodename);

        if (!has_correct_address(template, address))
                return NULL;

        la_command_t *const result = dup_command(template);

        result->pattern = NULL;
        init_list(&result->pattern_properties);

        result->address = address ? dup_address(address) : NULL;
        result->end_time = result->n_triggers = result->start_time= 0;
#ifndef CLIENTONLY
        result->submission_type = is_local_address(from_addr) ?
                LA_SUBMISSION_MANUAL : LA_SUBMISSION_REMOTE;
#else /* CLIENTONLY */
        result->submission_type = LA_SUBMISSION_MANUAL;
#endif /* CLIENTONLY */

        convert_both_commands(result);

        return result;
}

/*
 * Creates a new command template
 *
 * Duration = 0 prevents any end command
 * Duration = INT_MAX will result that the end command will only be fired on shutdown
 *
 * Note: pattern_properties will not be initialized by create_template() or
 * dup_command()
 *
 * FIXME: use another value than INT_MAX
 */

la_command_t *
create_template(const char *const name, la_rule_t *const rule,
                const char *const begin_string, const char *const end_string,
                const int duration, const la_need_host_t need_host,
                const bool quick_shutdown)
{
        assert(name); assert_rule(rule); assert(begin_string);
        la_debug("create_template(%s, %d)", name, duration);

        la_command_t *const result = create_node0(sizeof *result, 0, name);

        result->id = ++id_counter;
        result->is_template = true;

        result->adr_node.payload = result;

        result->begin_string = xstrdup(begin_string);
        result->n_begin_properties =
                scan_action_tokens(&result->begin_properties, begin_string);

        result->end_string = xstrdup(end_string);
        result->n_end_properties = end_string ?
                scan_action_tokens(&result->end_properties, end_string) : 0;

        result->rule = rule;
        result->need_host = need_host;
        result->quick_shutdown = quick_shutdown;

        result->duration = duration;
        result->factor = 1;

        /* Will be used to restore queue counters on reload. Yes, it's a bit
         * ugly but such is life... */
        result->rule_name = xstrdup(rule->node.nodename);

        init_list(&result->pattern_properties);

        return result;
}

/*
 * Free single command. Does nothing when argument is NULL
 *
 * Runs in end_queue_thread
 */

void
free_command(la_command_t *const command)
{
        if (!command)
                return;

        la_vdebug("free_command(%s)", command->node.nodename);

        free(command->node.nodename);

        free(command->begin_string);
        free(command->begin_string_converted);
        free(command->end_string);
        free(command->end_string_converted);
        empty_property_list(&command->begin_properties);
        empty_property_list(&command->end_properties);
        empty_property_list(&command->pattern_properties);
        free(command->rule_name);

        free_address(command->address);
        free(command);
}

#ifndef CLIENTONLY
const char *
command_address_on_dnsbl(const la_command_t *const command)
{
        assert_command(command);
        return host_on_any_dnsbl(&command->rule->blacklists, command->address);
}
#endif /* CLIENTONLY */

/* vim: set autowrite expandtab: */
