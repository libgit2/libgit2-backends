#ifndef __LIBGIT2_MYSQL_ODB_H
#define __LIBGIT2_MYSQL_ODB_H

#include <stdint.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <mysql.h>
#pragma GCC diagnostic pop

#include <git2.h>
#include <git2/errors.h>
#include <git2/odb_backend.h>
#include <git2/sys/odb_backend.h>
#include <git2/types.h>

int git_odb_backend_mysql(git_odb_backend **backend_out,
        MYSQL *db,
        const char *mysql_table,
        uint32_t git_repository_id,
        int odb_partitions);

#endif
