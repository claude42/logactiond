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

#ifndef __configfile_h
#define __configfile_h

#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>

#include <libconfig.h>

#include "ndebug.h"
#include "sources.h"

#define DEFAULT_THRESHOLD 3
#define DEFAULT_PERIOD 600
#define DEFAULT_DURATION 600

#define DEFAULT_META_ENABLED false
#define DEFAULT_META_PERIOD 3600
#define DEFAULT_META_FACTOR 2
#define DEFAULT_META_MAX 86400

#define DEFAULT_DNSBL_ENABLED false

#define DEFAULT_PORT 16473

#define DEFAULT_STATE_SAVE_PERIOD 300

#define LA_DEFAULTS_LABEL "defaults"

#define LA_PROPERTIES_LABEL "properties"

#define LA_THRESHOLD_LABEL "threshold"
#define LA_PERIOD_LABEL "period"
#define LA_DURATION_LABEL "duration"
#define LA_DNSBL_DURATION_LABEL "dnsbl_duration"

#define LA_IGNORE_LABEL "ignore"

#define LA_META_ENABLED_LABEL "meta_enabled"
#define LA_META_PERIOD_LABEL "meta_period"
#define LA_META_FACTOR_LABEL "meta_factor"
#define LA_META_MAX_LABEL "meta_max"

#define LA_DNSBL_ENABLED_LABEL "dnsbl_enabled"

#define LA_SERVICE_LABEL "service"

#define LA_ACTIONS_LABEL "actions"
#define LA_ACTION_INITIALIZE_LABEL "initialize"
#define LA_ACTION_SHUTDOWN_LABEL "shutdown"
#define LA_ACTION_BEGIN_LABEL "begin"
#define LA_ACTION_END_LABEL "end"
#define LA_ACTION_NEED_HOST_LABEL "need_host"
#define LA_ACTION_NEED_HOST_NO_LABEL "no"
#define LA_ACTION_NEED_HOST_ANY_LABEL "any"
#define LA_ACTION_NEED_HOST_IP4_LABEL "4"
#define LA_ACTION_NEED_HOST_IP6_LABEL "6"
#define LA_ACTION_QUICK_SHUTDOWN_LABEL "quick_shutdown"

#define LA_SOURCES_LABEL "sources"

#define LA_LOCAL_LABEL "local"
#define LA_ENABLED_LABEL "enabled"

#define LA_BLACKLISTS_LABEL "blacklists"

#define LA_RULES_LABEL "rules"
#define LA_RULE_SOURCE_LABEL "source"
#define LA_RULE_ACTION_LABEL "action"
#define LA_RULE_PATTERNS_LABEL "pattern"
#define LA_RULE_SYSTEMD_UNIT_LABEL "systemd-unit"

#define LA_SOURCE_LOCATION "location"
#define LA_SOURCE_PREFIX "prefix"

#define LA_REMOTE_LABEL "remote"
#define LA_REMOTE_RECEIVE_FROM_LABEL "receive_from"
#define LA_REMOTE_SEND_TO_LABEL "send_to"
#define LA_REMOTE_SECRET_LABEL "secret"
#define LA_REMOTE_BIND_LABEL "bind"
#define LA_REMOTE_PORT_LABEL "port"

#define LA_FILES_LABEL "files"
#define LA_FILES_FIFO_PATH_LABEL "fifo_path"
#define LA_FILES_FIFO_USER_LABEL "fifo_user"
#define LA_FILES_FIFO_GROUP_LABEL "fifo_group"
#define LA_FILES_FIFO_MASK_LABEL "fifo_mask"

typedef struct la_config_s la_config_t;
typedef struct la_config_s
{
        config_t config_file;
        kw_list_t source_groups;
        la_source_group_t *systemd_source_group;
        int default_threshold;
        int default_period;
        int default_duration;
        int default_dnsbl_duration;
        int default_meta_enabled; /* should be bool but well... */
        int default_meta_period;
        int default_meta_factor;
        int default_meta_max;
        kw_list_t default_properties;
        kw_list_t ignore_addresses;
        int remote_enabled;
        kw_list_t remote_receive_from;
        kw_list_t remote_send_to;
        char *remote_secret;
        bool remote_secret_changed;
        char *remote_bind;
        int remote_port;
        int total_clocks;
        int invocation_count;
        char *fifo_path;
        uid_t fifo_user;
        gid_t fifo_group;
        mode_t fifo_mask;

} la_config_t;

extern la_config_t *la_config;

extern int id_counter;

extern pthread_mutex_t config_mutex;

bool init_la_config(const char *filename);

void load_la_config(void);

void unload_la_config(void);
#endif /* __configfile_h */

/* vim: set autowrite expandtab: */
