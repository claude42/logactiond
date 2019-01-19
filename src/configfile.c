#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <err.h>

#include <libconfig.h>

#include "logactiond.h"
#include "nodelist.h"

la_config_t *la_config;


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


int *
load_la_config(char *filename)
{
	la_config = (la_config_t *) xmalloc(sizeof(la_config_t));

	config_init(&la_config->config_file);

	/*config_set_include_func(&la_config->config_file, include_func);*/

	if (!filename)
		filename = CONFIG_FILE;

	if (!config_read_file(&la_config->config_file, filename))
		die_syntax();

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
