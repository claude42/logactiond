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

#ifndef __sources_h
#define __sources_h

#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>

#include "ndebug.h"
#include "nodelist.h"

#define ITERATE_SOURCES(SOURCES) (la_source_t *) &(SOURCES)->head
#define NEXT_SOURCE(SOURCE) (la_source_t *) (SOURCE->node.succ->succ ? SOURCE->node.succ : NULL)
#define HAS_NEXT_SOURCE(SOURCE) SOURCE->node.succ
#define REM_SOURCES_HEAD(SOURCES) (la_source_t *) rem_head(SOURCES)

#define ITERATE_SOURCE_GROUPS(SOURCE_GROUPS) (la_source_group_t *) &(SOURCE_GROUPS)->head
#define NEXT_SOURCE_GROUP(SOURCE_GROUP) (la_source_group_t *) (SOURCE_GROUP->node.succ->succ ? SOURCE_GROUP->node.succ : NULL)
#define HAS_NEXT_SOURCE_GROUP(SOURCE_GROUP) SOURCE_GROUP->node.succ
#define REM_SOURCE_GROUPS_HEAD(SOURCE_GROUPS) (la_source_group_t *) rem_head(SOURCE_GROUPS)

/* assertions */

#ifdef NDEBUG
#define assert_source(SOURCE) (void)(0)
#define assert_source_group(SOURCE_GROUP) (void)(0)
#else /* NDEBUG */
#define assert_source(SOURCE) assert_source_ffl(SOURCE, __func__, __FILE__, __LINE__)
#define assert_source_group(SOURCE_GROUP) assert_source_group_ffl(SOURCE_GROUP, __func__, __FILE__, __LINE__)
#endif /* NDEBUG */

typedef struct la_source_group_s la_source_group_t;
struct la_source_group_s
{
        struct kw_node_s node;
        /* Name of source in config file - strdup()d */
        char *name;
        /* Specified path, potentially glob pattern */
        char *glob_pattern;
        /* All source files */
        struct kw_list_s *sources;
        /* Rules assigned to log file */
        struct kw_list_s *rules;
        /* Prefix to prepend before rule patterns */
        char *prefix;
        /* Next one is only used in systemd.c */
        /* systemd_units we're interested in */
#if HAVE_LIBSYSTEMD
        struct kw_list_s *systemd_units;
#endif /* HAVE_LIBSYSTEMD */
};

/*
 * Represents a source
 */

typedef struct la_source_s la_source_t;
struct la_source_s
{
        struct kw_node_s node;
        /* Source list this source is part of */
        struct la_source_group_s *source_group;
        /* Filename (or equivalent) - strdup()d */
        char *location;
        /* File handle for log file */
        FILE *file;
        /* stat() result for file */
        struct stat stats;
        /* File is currently "watchable" - only used by polling backend */
        bool active;

#if HAVE_INOTIFY
        /* Next two are only used in inotify.c */

        /* Watch descriptor for log file itself */
        int wd;
        /* Watch descriptor for parent directory */
        int parent_wd;
#endif /* HAVE_INOTIFY */
};

void assert_source_ffl(const la_source_t *source, const char *func,
                const char *file, unsigned int line);

void assert_source_group_ffl(const la_source_group_t *source_group, const char *func,
                const char *file, unsigned int line);

void handle_log_line(const la_source_t *source, const char *line, const char *systemd_unit);

bool handle_new_content(const la_source_t *source);

la_source_group_t *create_source_group(const char *name,
                const char *glob_pattern, const char *prefix);

la_source_t *create_source(la_source_group_t *source_group, const char *location);

void free_source(la_source_t *source);

void free_source_group(la_source_group_t *source_group);

void free_source_group_list(kw_list_t *list);

la_source_group_t *find_source_group_by_location(const char *location);

la_source_group_t *find_source_group_by_name(const char *name);

void reset_counts(void);

#endif /* __sources_h */

/* vim: set autowrite expandtab: */
