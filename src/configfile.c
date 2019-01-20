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

#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/stat.h>
#include <syslog.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

la_config_t *la_config;

const char*
config_get_string_or_null(const config_setting_t *setting, const char *name)
{
	const char* result;
	if (!config_setting_lookup_string(setting, name, &result))
		result = NULL;

	return result;
}

int
config_get_unsigned_int_or_negative(const config_setting_t *setting,
		const char *name)
{
	int result;
	if (!config_setting_lookup_int(setting, name, &result))
		return -1;

	return result;
}

const char*
config_get_string_or_die( const config_setting_t *setting, const char *name)
{
	const char* result = config_get_string_or_null(setting, name);

	if (!result)
		die_semantic("config_get_string_or_die: Config element %s missingn\n", name);

	return result;
}

const config_setting_t
*config_setting_lookup_or_die( const config_setting_t *setting,
		const char *path)
{
	const config_setting_t *result;
	/* TODO: not sure why config_setting_t * (without const) is required
	 * here but nowhere else */
	result = config_setting_lookup((config_setting_t *) setting, path);
	if (!result)
		die_semantic("Missing element %s\n", path);

	return result;
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
	return config_setting_lookup_or_die(config_lookup(
				&la_config->config_file,
				LA_ACTIONS_LABEL), action_name);
}

/*
 * Returns a config_setting_t to a pattern within the main patterns section -
 * specified by the pattern_name.
 *
 * Returns NULL in case no pattern with that name exists
 */

const config_setting_t *
get_pattern(const char *pattern_name)
{
	return config_setting_lookup_or_die(config_lookup(
				&la_config->config_file,
				LA_PATTERNS_LABEL), pattern_name);
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
		die_semantic(LA_SOURCES_LABEL " section missing.");

	result = config_setting_lookup(sources_section, source);

	return  result;
}

const char
*get_source_name(const config_setting_t *rule)
{
	config_setting_t *source_def;
	const char *result;

	source_def = get_source(config_get_string_or_null(rule, LA_RULE_SOURCE_LABEL));
	if (!source_def)
		die_semantic("Source not found for rule %s\n", config_setting_name(rule));

	result = config_setting_name(source_def);
	if (!result)
		die_semantic("Source name missing\n");

	return result;
}

const char
*get_source_location(const config_setting_t *rule)
{
	config_setting_t *source_def;
	const char *result;

	source_def = get_source(config_get_string_or_null(rule, LA_RULE_SOURCE_LABEL));
	if (!source_def)
		die_semantic("Source not found for rule %s\n", config_setting_name(rule));

	if (!config_setting_lookup_string(source_def, LA_LOCATION, &result))
		die_semantic("Source location missing\n");

	return result;
}

la_sourcetype_t
get_source_type(const config_setting_t *rule)
{
	config_setting_t *source_def;
	const char *type;

	source_def = get_source(config_get_string_or_die(rule, LA_RULE_SOURCE_LABEL));
	if (!source_def)
		die_semantic("Source not found");

	type = config_get_string_or_die(rule, LA_RULE_TYPE_LABEL);

	if (!strcmp(type, LA_RULE_TYPE_FILE_OPTION))
		return LA_RULE_TYPE_FILE;
	else if (!strcmp(type, LA_RULE_TYPE_SYSTEMD_OPTION))
		return LA_RULE_TYPE_SYSTEMD;
	else
		die_semantic("Wrong source type \"%s\" specified\n.", type);

	return 0; // avoid warning
}

/*
 * Add struct la_action_s to existing actions
 */

static void
compile_actions(la_rule_t *rule, const config_setting_t *action_def)
{
	la_action_t *la_action = create_action(
			config_setting_name(action_def),
			rule,
			config_get_string_or_null(action_def,
				LA_ACTION_INITIALIZE_LABEL),
			config_get_string_or_null(action_def,
				LA_ACTION_SHUTDOWN_LABEL),
			config_get_string_or_die(action_def,
				LA_ACTION_BEGIN_LABEL),
			config_get_string_or_null(action_def,
				LA_ACTION_END_LABEL));

	add_tail(rule->actions, (kw_node_t *) la_action);
}

static void
compile_list_of_actions(la_rule_t *rule,
		const config_setting_t *action_def)
{
	int n_items = config_setting_length(action_def);

	for (int i=0; i<n_items; i++)
	{
		config_setting_t *list_item =
			config_setting_get_elem(action_def, i);
		compile_actions(rule,
				get_action(config_setting_get_string(
						list_item)));
	}
}

/*
 * Return a list of all actions (i.e. struct la_action_s) assigned to a rule
 */

static void
load_actions(la_rule_t *rule, const config_setting_t *rule_def)
{
	const config_setting_t *action_reference =
		config_setting_lookup_or_die(rule_def, LA_RULE_ACTION_LABEL);
	int type = config_setting_type(action_reference);

	if (type == CONFIG_TYPE_STRING)
		compile_actions(rule, get_action(
					config_setting_get_string(
						action_reference)));
	else if (type == CONFIG_TYPE_LIST)
		compile_list_of_actions(rule, action_reference);
	else
		die_semantic("Element neither string nor list");
}

static void
compile_matches(la_rule_t *rule,
		const config_setting_t *pattern_section)
{
	if (!pattern_section)
		die_semantic("Missing patterns section %s\n",
				config_setting_get_string(pattern_section));

	int n = config_setting_length(pattern_section);
	if (n < 0)
		die_semantic("No patterns specified for %s\n",
				config_setting_name(pattern_section));

	for (int i=0; i<n; i++)
	{
		const char *item = config_setting_get_string_elem(pattern_section, i);

		la_pattern_t *pattern = create_pattern(item, rule);

		add_tail(rule->patterns, (kw_node_t *) pattern);
	}
}

static void
compile_list_of_matches(la_rule_t *rule,
		const config_setting_t *pattern_reference)
{
	int n_items = config_setting_length(pattern_reference);

	for (int i=0; i<n_items; i++)
	{
		config_setting_t *list_item =
			config_setting_get_elem(pattern_reference, i);
		compile_matches(rule,
				get_pattern(config_setting_get_string(
						list_item)));
	}
}


/*
 * Return a list of all patterns (i.e. regex strings) assigned to a rule
 */

static void
load_patterns(la_rule_t *rule, const config_setting_t *rule_def)
{
	const config_setting_t *pattern_reference =
		config_setting_lookup_or_die(rule_def, LA_RULE_PATTERN_LABEL);
	int type = config_setting_type(pattern_reference);

	if (type == CONFIG_TYPE_STRING)
		compile_matches(rule, get_pattern(
					config_setting_get_string(
						pattern_reference)));
	else if (type == CONFIG_TYPE_LIST)
		compile_list_of_matches(rule, pattern_reference);
	else
		die_semantic("Element neither string nor list");
}

static kw_list_t *
load_ignore_addresses(const config_setting_t *section)
{
	la_debug("load_ignore_addresses(%s)\n", config_setting_name(section));
	kw_list_t *result = create_list();

	config_setting_t *ignore_section =
		config_setting_get_member(section, "ignore");

	if (!ignore_section)
		return result;

	int n = config_setting_length(ignore_section);
	for (int i=0; i<n; i++)
	{
		config_setting_t *elem =
			config_setting_get_elem(ignore_section, i);
		const char *ip = config_setting_get_string(elem);
		if (!ip)
			die_hard("Only strings allowed for ignore addresses!\n");

		la_address_t *address = create_address(ip);

		la_debug("Loaded ignore addr %s from section %s\n", ip, config_setting_name(section));
		add_tail(result, (kw_node_t *) address);
	}

	return result;
}


static kw_list_t *
load_properties(const config_setting_t *section)
{
	la_debug("load_properties(%s)\n", config_setting_name(section));
	kw_list_t *result = create_list();

	config_setting_t *properties_section =
		config_setting_get_member(section, LA_PROPERTIES_LABEL);

	if (!properties_section)
		return result;

	int n = config_setting_length(properties_section);
	for (int i=0; i<n; i++)
	{
		config_setting_t *elem =
			config_setting_get_elem(properties_section, i);
		const char *name = config_setting_name(elem);
		if (!name)
			die_hard("Property without a name?!\n");
		const char *value = config_setting_get_string(elem);
		if (!value)
			die_hard("Only strings allowed for properties!\n");

		la_property_t *property = create_property_from_config(name, value);

		la_debug("Loaded prop %s from section %s\n", name, config_setting_name(section));
		add_tail(result, (kw_node_t *) property);
	}

	return result;
}



static void
load_single_rule(const config_setting_t *rule_def)
{
	char *name;
	la_rule_t *new_rule;
	la_source_t *source;
	const char *location;
	la_sourcetype_t type;

	name = config_setting_name(rule_def);

	location = get_source_location(rule_def);
	source = find_source_by_location(location);
	if (!source)
	{
		source = create_source(get_source_name(rule_def),
				get_source_type(rule_def), location);
		watch_source(source, SEEK_END);

		add_tail(la_config->sources, (kw_node_t *) source);
	}

	new_rule = create_rule(config_setting_name(rule_def), source,
			config_get_unsigned_int_or_negative(rule_def,
				LA_THRESHOLD_LABEL),
			config_get_unsigned_int_or_negative(rule_def,
				LA_PERIOD_LABEL),
			config_get_unsigned_int_or_negative(rule_def,
				LA_DURATION_LABEL));
	new_rule->properties = load_properties(rule_def);
	load_patterns(new_rule, rule_def);
	load_actions(new_rule, rule_def);
	add_tail(source->rules, (kw_node_t *) new_rule);
}


static void
load_rules(void)
{
	config_setting_t *rules_section =
		config_lookup(&la_config->config_file, LA_RULES_LABEL);

	la_config->sources = create_list();

	int n = config_setting_length(rules_section);
	la_debug("load_rules(), n=%u\n", n);
	if (n < 0)
		die_semantic("No rules specified");

	for (int i=0; i<n; i++)
		load_single_rule(config_setting_get_elem(rules_section, i));
}

static void
load_defaults(void)
{
	config_setting_t *defaults_section =
		config_lookup(&la_config->config_file, LA_DEFAULTS_LABEL);

	if (defaults_section)
	{
		la_config->default_threshold =
			config_get_unsigned_int_or_negative(defaults_section,
					LA_THRESHOLD_LABEL);
		la_config->default_period =
			config_get_unsigned_int_or_negative(defaults_section,
					LA_PERIOD_LABEL);
		la_config->default_duration =
			config_get_unsigned_int_or_negative(defaults_section,
					LA_DURATION_LABEL);

		la_config->default_properties = load_properties(defaults_section);
		la_config->ignore_addresses = load_ignore_addresses(defaults_section);
	}
	else
	{
		la_config->default_threshold = -1;
		la_config->default_period = -1;
		la_config->default_duration = -1;
		la_config->default_properties = NULL;
		la_config->ignore_addresses = NULL;
	}
}

const char ** include_func(config_t *config, const char *include_dir, const
                char *path, const char **error);

int *
load_la_config(char *filename)
{
	la_config = (la_config_t *) xmalloc(sizeof(la_config_t));

        config_init(&la_config->config_file);

        config_set_include_func(&la_config->config_file, include_func);

        if (!config_read_file(&la_config->config_file,
                                filename ? filename : CONFIG_FILE))
        {
                die_hard("%s:%d - %s\n",
                                config_error_file(&la_config->config_file),
                                config_error_line(&la_config->config_file),
                                config_error_text(&la_config->config_file));
        }

	init_watching();

	load_defaults();

	load_rules();

	return 0;
}

void
unload_la_config(void)
{
        config_destroy(&la_config->config_file);
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

                        la_log(LOG_DEBUG, "file: %s\n", file_path);
		}
		closedir(dp);
	}

	*result_next = NULL;

	return ((const char **)result);
}

/* vim: set autowrite expandtab: */
