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
#include <sys/inotify.h>
#include <sys/select.h>
#include <err.h>

#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/stat.h>

#include <libconfig.h>

#include "logactiond.h"

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
}

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

			printf("file: %s\n", file_path);
		}
		closedir(dp);
	}

	*result_next = NULL;

	return ((const char **)result);
}


/* vim: set autowrite expandtab: */
