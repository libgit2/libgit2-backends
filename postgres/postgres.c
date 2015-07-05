/*
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * In addition to the permissions in the GNU General Public License,
 * the authors give you unlimited permission to link the compiled
 * version of this file into combinations with other programs,
 * and to distribute those combinations without any restriction
 * coming from the use of this file.  (The General Public License
 * restrictions do apply in other respects; for example, they cover
 * modification of the file, and distribution when not linked into
 * a combined executable.)
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
 
#include <assert.h>
#include <string.h>
#include <git2.h>
#include <git2/odb_backend.h>
#include <postgresql/libpq-fe.h>

#define GIT2_TABLE_NAME "git2_odb"
#define GIT2_SCHEMA_NAME "git2"

typedef struct {
	git_odb_backend parent;
	PGconn *db;
} postgres_backend;

int postgres_backend__read_header(size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	postgres_backend *backend;
	int error;
	PGresult *result;

	assert(len_p && type_p && _backend && oid);

	backend = (postgres_backend *)_backend;
	error = GIT_ERROR;
	
	result = PQexecParams(backend->db, "SELECT type, size FROM " GIT2_SCHEMA_NAME "." GIT2_TABLE_NAME " WHERE oid = $1;", 1, NULL, (const char**)(&(oid->id)), NULL, NULL, 0);
	if(PQresultStatus(result) != PGRES_TUPLES_OK){
		return GIT_ERROR;
	}
	
	if(PQntuples(result) < 1){
		error = GIT_ENOTFOUND;
	}
	else{
		assert(PQntuples(result) == 1);
		
		*type_p = (git_otype)strtol(PQgetvalue(result, 0, 0), NULL, 10);
		*len_p = (git_otype)strtol(PQgetvalue(result, 0, 1), NULL, 10);
		error = GIT_SUCCESS;
	}

	PQclear(result);
	return error;
}

int postgres_backend__read(void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	postgres_backend *backend;
	int error;
	PGresult *result;

	assert(data_p && len_p && type_p && _backend && oid);

	backend = (postgres_backend *)_backend;
	error = GIT_ERROR;

	result = PQexecParams(backend->db, "SELECT type, size, data FROM " GIT2_SCHEMA_NAME "." GIT2_TABLE_NAME " WHERE oid = $1;", 1, NULL, (const char**)(&(oid->id)), NULL, NULL, 0);
	if(PQresultStatus(result) != PGRES_TUPLES_OK){
		return GIT_ERROR;
	}
	
	if(PQntuples(result) < 1){
		error = GIT_ENOTFOUND;
	}
	else{
		assert(PQntuples(result) == 1);
		
		*type_p = (git_otype)strtol(PQgetvalue(result, 0, 0), NULL, 10);
		*len_p = (git_otype)strtol(PQgetvalue(result, 0, 1), NULL, 10);
		*data_p = malloc(*len_p);

		if (*data_p == NULL) {
			error = GIT_ENOMEM;
		} else {
			memcpy(*data_p, PQgetvalue(result, 0, 2), *len_p);
			error = GIT_SUCCESS;
		}
		
		error = GIT_SUCCESS;
	}

	PQclear(result);
	return error;
}

int postgres_backend__read_prefix(git_oid *out_oid, void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend,
					const git_oid *short_oid, unsigned int len) {
	if (len >= GIT_OID_HEXSZ) {
		/* Just match the full identifier */
		int error = postgres_backend__read(data_p, len_p, type_p, _backend, short_oid);
		if (error == GIT_SUCCESS)
			git_oid_cpy(out_oid, short_oid);

		return error;
	} else if (len < GIT_OID_HEXSZ) {
		return GIT_ENOTIMPLEMENTED;
	}
}

int postgres_backend__exists(git_odb_backend *_backend, const git_oid *oid)
{
	postgres_backend *backend;
	int found;
	PGresult *result;

	assert(_backend && oid);

	backend = (postgres_backend *)_backend;
	found = 0;
	
	result = PQexecParams(backend->db, "SELECT type, size, data FROM " GIT2_SCHEMA_NAME "." GIT2_TABLE_NAME " WHERE oid = $1;", 1, NULL, (const char**)(&(oid->id)), NULL, NULL, 0);
	if(PQresultStatus(result) != PGRES_TUPLES_OK){
		return GIT_ERROR;
	}

	if(PQntuples(result) > 0){
		found = 1;
	}

	PQclear(result);
	return found;
}

int postgres_backend__write(git_oid *id, git_odb_backend *_backend, const void *data, size_t len, git_otype type)
{
	int error;
	postgres_backend *backend;
	PGresult *result;
	
	//this is a rather ugly construct to avoid having to know about postgres' internal integer representation
	char type_str[128];
	char size_str[128];
	
	const char *values[4] = {(char*)id->id, type_str, size_str, (char*)data};
	const int lengths[4] = {0, 0, 0, len};
	const int formats[4] = {0, 0, 0, 1};
	
	assert(id && _backend && data);

	backend = (postgres_backend *)_backend;

	if ((error = git_odb_hash(id, data, len, type)) < 0)
		return error;

	snprintf(type_str, sizeof(type_str), "%d", type);
	snprintf(size_str, sizeof(size_str), "%d", len);
	
	result = PQexecParams(backend->db, "INSERT INTO " GIT2_SCHEMA_NAME "." GIT2_TABLE_NAME "' VALUES ($1, $2, $3, $4);", 4, NULL, values, lengths, formats, 0);

	error = PQresultStatus(result);
	PQclear(result);
	
	return (error == PGRES_COMMAND_OK || error == PGRES_TUPLES_OK) ? GIT_SUCCESS : GIT_ERROR;
}

void postgres_backend__free(git_odb_backend *_backend)
{
	postgres_backend *backend;
	assert(_backend);
	backend = (postgres_backend *)_backend;

	PQfinish(backend->db);

	free(backend);
}

static int create_table(PGconn *db)
{
	PGresult *result;
	
	static const char *schema_create = 
		"CREATE SCHEMA IF NOT EXISTS " GIT2_SCHEMA_NAME;
	
	static const char *sql_creat =
		"CREATE TABLE " GIT2_SCHEMA_NAME "." GIT2_TABLE_NAME "' ("
		"'oid' TEXT PRIMARY KEY NOT NULL,"
		"'type' INTEGER NOT NULL,"
		"'size' INTEGER NOT NULL,"
		"'data' BLOB);";

	result = PQexec(db, schema_create);
	if(PQresultStatus(result) != PGRES_COMMAND_OK && PQresultStatus(result) != PGRES_TUPLES_OK){
		return GIT_ERROR;
	}
	
	result = PQexec(db, sql_creat);
	if(PQresultStatus(result) != PGRES_COMMAND_OK && PQresultStatus(result) != PGRES_TUPLES_OK){
		return GIT_ERROR;
	}

	return GIT_SUCCESS;
}

static int init_db(PGconn *db)
{
	PGresult *result;
	static const char *sql_check = "SELECT EXISTS ( SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
							" WHERE n.nspname = '"GIT2_SCHEMA_NAME"' AND c.relname = '"GIT2_TABLE_NAME"' AND c.relkind = 'r');";
	
	result = PQexec(db, sql_check);
	if(PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) < 1){
		PQClear(result);
		return create_table(db);
	}
	
	return GIT_SUCCESS;
}

int pq_connect(PGconn **db, const char *host, unsigned port, const char *dbname, const char *user, const char *password){
	char port_str[10];
	
	snprintf(port_str, sizeof(port_str), "%d", port);
	
	char const *keywords[] = {"host", "port", "dbname", "user",  (password)?"password":NULL,  NULL};
	const char *values[] = {host, port_str, dbname, user, password, NULL};

	*db = PQconnectdbParams(keywords, (char const**)values, 0);

	if(!(*db)){
		return 1;
	}

	if(PQstatus(*db) != CONNECTION_OK){
		PQfinish(*db);
		return 1;
	}

	return 0;
}

int git_odb_backend_postgres(git_odb_backend **backend_out, const char *pg_host,
        const char *pg_user, const char *pg_passwd, const char *pg_db, unsigned int pg_port)
{
	postgres_backend *backend;
	int error;

	backend = calloc(1, sizeof(postgres_backend));
	if (backend == NULL)
		return GIT_ENOMEM;

	if(pq_connect(&(backend->db), pg_host, pg_port, pg_db, pg_user, pg_passwd)){
		goto cleanup;
	}

	// check for and possibly create the database
	error = init_db(backend->db);
	if (error < 0)
		goto cleanup;

	backend->parent.read = &postgres_backend__read;
	backend->parent.read_header = &postgres_backend__read_header;
	backend->parent.write = &postgres_backend__write;
	backend->parent.exists = &postgres_backend__exists;
	backend->parent.free = &postgres_backend__free;

	*backend_out = (git_odb_backend *)backend;
	return GIT_SUCCESS;

	cleanup:
		postgres_backend__free((git_odb_backend *)backend);
		return GIT_ERROR;
}
