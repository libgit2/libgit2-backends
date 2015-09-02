#ifndef __LIBGIT2_MYSQL_REFDB_H
#define __LIBGIT2_MYSQL_REFDB_H

/* disable -Wstrict-prototypes because mysql's devs don't know C ... */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <mysql.h>
#pragma GCC diagnostic pop

#include <git2.h>
#include <git2/errors.h>
#include <git2/refdb.h>
#include <git2/sys/refdb_backend.h>
#include <git2/types.h>

int git_refdb_backend_mysql(git_refdb_backend **backend_out,
        MYSQL *db,
        const char *mysql_table,
        uint32_t git_repository_id,
        int refdb_partitions);

#endif
