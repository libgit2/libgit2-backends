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
#include <git2/sys/odb_backend.h>
#include <hiredis/hiredis.h>

typedef struct {
	git_odb_backend parent;

	const char *prefix;
	const char *repo_path;
	redisContext *db;
} hiredis_odb_backend;

int hiredis_odb_backend__read_header(size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	hiredis_odb_backend *backend;
	int error;
	redisReply *reply;
	char *str_id = calloc(GIT_OID_HEXSZ + 1, sizeof(char));

	assert(len_p && type_p && _backend && oid);

	backend = (hiredis_odb_backend *) _backend;
	error = GIT_ERROR;

	git_oid_tostr(str_id, GIT_OID_HEXSZ, oid);

	reply = redisCommand(backend->db, "HMGET %s:%s:odb:%s %s %s", backend->prefix, backend->repo_path, str_id, "type", "size");

	if (reply && reply->type == REDIS_REPLY_ARRAY) {
		if (reply->element[0]->type != REDIS_REPLY_NIL &&
				reply->element[0]->type != REDIS_REPLY_NIL) {
			*type_p = (git_otype) atoi(reply->element[0]->str);
			*len_p = (size_t) atoi(reply->element[1]->str);
			error = GIT_OK;
		} else {
			giterr_set_str(GITERR_ODB, "Redis odb storage corrupted");
			error = GIT_ENOTFOUND;
		}
	} else {
		giterr_set_str(GITERR_ODB, "Redis odb storage error");
		error = GIT_ERROR;
	}

	free(str_id);
	freeReplyObject(reply);
	return error;
}

int hiredis_odb_backend__read(void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	hiredis_odb_backend *backend;
	int error;
	redisReply *reply;
	char *str_id = calloc(GIT_OID_HEXSZ + 1, sizeof(char));

	assert(data_p && len_p && type_p && _backend && oid);

	backend = (hiredis_odb_backend *) _backend;
	error = GIT_ERROR;

	git_oid_tostr(str_id, GIT_OID_HEXSZ, oid);

	reply = redisCommand(backend->db, "HMGET %s:%s:odb:%s %s %s %s", backend->prefix, backend->repo_path, str_id,
			"type", "size", "data");

	if (reply && reply->type == REDIS_REPLY_ARRAY) {
		if (reply->element[0]->type != REDIS_REPLY_NIL &&
				reply->element[1]->type != REDIS_REPLY_NIL &&
				reply->element[2]->type != REDIS_REPLY_NIL) {
			*type_p = (git_otype) atoi(reply->element[0]->str);
			*len_p = (size_t) atoi(reply->element[1]->str);
			*data_p = malloc(*len_p);
			if (*data_p == NULL) {
				error = GITERR_NOMEMORY;
			} else {
				memcpy(*data_p, reply->element[2]->str, *len_p);
				error = GIT_OK;
			}
		} else {
			giterr_set_str(GITERR_ODB, "Redis odb couldn't find object");
			error = GIT_ENOTFOUND;
		}
	} else {
		giterr_set_str(GITERR_ODB, "Redis odb storage error");
		error = GIT_ERROR;
	}

	free(str_id);
	freeReplyObject(reply);
	return error;
}

int hiredis_odb_backend__read_prefix(git_oid *out_oid,
		void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend,
		const git_oid *short_oid, size_t len)
{
	if (len >= GIT_OID_HEXSZ) {
		/* Just match the full identifier */
		int error = hiredis_odb_backend__read(data_p, len_p, type_p, _backend, short_oid);
		if (error == GIT_OK)
			git_oid_cpy(out_oid, short_oid);

		return error;
	}

	/* TODO prefix */
	giterr_set_str(GITERR_ODB, "Redis odb doesn't not implement oid prefix lookup");
	return GITERR_INVALID;
}

int hiredis_odb_backend__exists(git_odb_backend *_backend, const git_oid *oid)
{
	hiredis_odb_backend *backend;
	int found;
	redisReply *reply;
	char *str_id = calloc(GIT_OID_HEXSZ + 1, sizeof(char));

	assert(_backend && oid);

	backend = (hiredis_odb_backend *) _backend;
	found = 0;

	git_oid_tostr(str_id, GIT_OID_HEXSZ, oid);

	reply = redisCommand(backend->db, "exists %s:%s:odb:%s", backend->prefix, backend->repo_path, str_id);
	if (reply->type == REDIS_REPLY_INTEGER)
		found = reply->integer;

	free(str_id);
	freeReplyObject(reply);
	return found;
}

int hiredis_odb_backend__write(git_odb_backend *_backend, const git_oid *oid, const void *data, size_t len, git_otype type)
{
	hiredis_odb_backend *backend;
	int error;
	redisReply *reply;
	char *str_id = calloc(GIT_OID_HEXSZ + 1, sizeof(char));

	assert(oid && _backend && data);

	backend = (hiredis_odb_backend *) _backend;
	error = GIT_ERROR;

	git_oid_tostr(str_id, GIT_OID_HEXSZ, oid);

	reply = redisCommand(backend->db, "HMSET %s:%s:odb:%s "
			"type %d "
			"size %d "
			"data %b ", backend->prefix, backend->repo_path, str_id,
			(int) type, len, data, len);
	free(str_id);

	error = (reply == NULL || reply->type == REDIS_REPLY_ERROR) ? GIT_ERROR : GIT_OK;

	freeReplyObject(reply);
	return error;
}

void hiredis_odb_backend__free(git_odb_backend *_backend)
{
	hiredis_odb_backend *backend;

	assert(_backend);
	backend = (hiredis_odb_backend *) _backend;

	redisFree(backend->db);

	free(backend);
}

int git_odb_backend_hiredis(git_odb_backend **backend_out, const char* prefix, const char* path, const char *host, int port)
{
	hiredis_odb_backend *backend;

	backend = calloc(1, sizeof (hiredis_odb_backend));
	if (backend == NULL)
		return GITERR_NOMEMORY;

	backend->db = redisConnect(host, port);
	if (backend->db->err) {
		free(backend);
		giterr_set_str(GITERR_REFERENCE, "Redis refdb storage couldn't connect to redis server");
		return GIT_ERROR;
	}

	backend->prefix = prefix;
	backend->repo_path = path;

	backend->parent.version = 1;

	backend->parent.read = &hiredis_odb_backend__read;
	backend->parent.write = &hiredis_odb_backend__write;
	backend->parent.read_prefix = &hiredis_odb_backend__read_prefix;
	backend->parent.read_header = &hiredis_odb_backend__read_header;
	backend->parent.exists = &hiredis_odb_backend__exists;
	backend->parent.free = &hiredis_odb_backend__free;

	backend->parent.writestream = NULL;
	backend->parent.foreach = NULL;

	*backend_out = (git_odb_backend *) backend;

	return GIT_OK;
}
