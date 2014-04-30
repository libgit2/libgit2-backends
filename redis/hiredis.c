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
#include <git2/sys/refdb_backend.h>
#include <git2/sys/refs.h>
#include <hiredis/hiredis.h>

typedef struct {
	git_odb_backend parent;

	char *prefix;
	char *repo_path;
	redisContext *db;
} hiredis_odb_backend;

typedef struct {
	git_refdb_backend parent;

	char *prefix;
	char *repo_path;
	redisContext *db;
} hiredis_refdb_backend;

typedef struct {
	git_reference_iterator parent;

	size_t current;
	redisReply *keys;

	hiredis_refdb_backend *backend;
} hiredis_refdb_iterator;

static redisContext *sharedConnection = NULL;

/* Odb methods */

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

	free(backend->repo_path);
	free(backend->prefix);

	redisFree(backend->db);

	free(backend);
}

/* Refdb methods */

int hiredis_refdb_backend__exists(int *exists, git_refdb_backend *_backend, const char *ref_name)
{
	hiredis_refdb_backend *backend;
	int error = GIT_OK;
	redisReply *reply;

	assert(ref_name && _backend);

	backend = (hiredis_refdb_backend *) _backend;

	reply = redisCommand(backend->db, "EXISTS %s:%s:refdb:%s", backend->prefix, backend->repo_path, ref_name);
	if (reply->type == REDIS_REPLY_INTEGER) {
		*exists = reply->integer;
	} else {
		giterr_set_str(GITERR_REFERENCE, "Redis refdb storage error");
		error = GIT_ERROR;
	}

	freeReplyObject(reply);
	return error;
}

int hiredis_refdb_backend__lookup(git_reference **out, git_refdb_backend *_backend, const char *ref_name)
{
	hiredis_refdb_backend *backend;
	int error = GIT_OK;
	redisReply *reply;
	git_oid oid;

	assert(ref_name && _backend);

	backend = (hiredis_refdb_backend *) _backend;

	reply = redisCommand(backend->db, "HMGET %s:%s:refdb:%s type target", backend->prefix, backend->repo_path, ref_name);
	if(reply->type == REDIS_REPLY_ARRAY) {
		if (reply->element[0]->type != REDIS_REPLY_NIL && reply->element[1]->type != REDIS_REPLY_NIL) {
			git_ref_t type = (git_ref_t) atoi(reply->element[0]->str);

			if (type == GIT_REF_OID) {
				git_oid_fromstr(&oid, reply->element[1]->str);
				*out = git_reference__alloc(ref_name, &oid, NULL);
			} else if (type == GIT_REF_SYMBOLIC) {
				*out = git_reference__alloc_symbolic(ref_name, reply->element[1]->str);
			} else {
				giterr_set_str(GITERR_REFERENCE, "Redis refdb storage corrupted (unknown ref type returned)");
				error = GIT_ERROR;
			}

		} else {
			giterr_set_str(GITERR_REFERENCE, "Redis refdb couldn't find ref");
			error = GIT_ENOTFOUND;
		}
	} else {
		giterr_set_str(GITERR_REFERENCE, "Redis refdb storage error");
		error = GIT_ERROR;
	}

	freeReplyObject(reply);
	return error;
}

int hiredis_refdb_backend__iterator_next(git_reference **ref, git_reference_iterator *_iter) {
	hiredis_refdb_iterator *iter;
	hiredis_refdb_backend *backend;
	char* ref_name;
	int error;

	assert(_iter);
	iter = (hiredis_refdb_iterator *) _iter;

	if(iter->current < iter->keys->elements) {
		ref_name = strstr(iter->keys->element[iter->current++]->str, ":refdb:") + 7;
		error = hiredis_refdb_backend__lookup(ref, (git_refdb_backend *) iter->backend, ref_name);

		return error;
	} else {
		return GIT_ITEROVER;
	}
}

int hiredis_refdb_backend__iterator_next_name(const char **ref_name, git_reference_iterator *_iter) {
	hiredis_refdb_iterator *iter;

	assert(_iter);
	iter = (hiredis_refdb_iterator *) _iter;

	if(iter->current < iter->keys->elements) {
		*ref_name = strdup(strstr(iter->keys->element[iter->current++]->str, ":refdb:") + 7);

		return GIT_OK;
	} else {
		return GIT_ITEROVER;
	}
}

void hiredis_refdb_backend__iterator_free(git_reference_iterator *_iter) {
	hiredis_refdb_iterator *iter;

	assert(_iter);
	iter = (hiredis_refdb_iterator *) _iter;

	freeReplyObject(iter->keys);

	free(iter);
}

int hiredis_refdb_backend__iterator(git_reference_iterator **_iter, struct git_refdb_backend *_backend, const char *glob)
{
	hiredis_refdb_backend *backend;
	hiredis_refdb_iterator *iterator;
	int error = GIT_OK;
	redisReply *reply;

	assert(_backend);

	backend = (hiredis_refdb_backend *) _backend;

	reply = redisCommand(backend->db, "KEYS %s:%s:refdb:%s", backend->prefix, backend->repo_path, (glob != NULL ? glob : "refs/*"));
	if(reply->type != REDIS_REPLY_ARRAY) {
		freeReplyObject(reply);
		giterr_set_str(GITERR_REFERENCE, "Redis refdb storage error");
		return GIT_ERROR;
	}

	iterator = calloc(1, sizeof(hiredis_refdb_iterator));

	iterator->backend = backend;
	iterator->keys = reply;

	iterator->parent.next = &hiredis_refdb_backend__iterator_next;
	iterator->parent.next_name = &hiredis_refdb_backend__iterator_next_name;
	iterator->parent.free = &hiredis_refdb_backend__iterator_free;

	*_iter = (git_reference_iterator *) iterator;

	return GIT_OK;
}

int hiredis_refdb_backend__write(git_refdb_backend *_backend, const git_reference *ref, int force, const git_signature *who,
	const char *message, const git_oid *old, const char *old_target)
{
	hiredis_refdb_backend *backend;
	int error = GIT_OK;
	redisReply *reply;

	const char *name = git_reference_name(ref);
	const git_oid *target;
	const char *symbolic_target;
	char oid_str[GIT_OID_HEXSZ + 1];

	assert(ref && _backend);

	backend = (hiredis_refdb_backend *) _backend;

	target = git_reference_target(ref);
	symbolic_target = git_reference_symbolic_target(ref);

	/* FIXME handle force correctly */

	if (target) {
		git_oid_nfmt(oid_str, sizeof(oid_str), target);
		reply = redisCommand(backend->db, "HMSET %s:%s:refdb:%s type %d target %s", backend->prefix, backend->repo_path, name, GIT_REF_OID, oid_str);
	} else {
		symbolic_target = git_reference_symbolic_target(ref);
		reply = redisCommand(backend->db, "HMSET %s:%s:refdb:%s type %d target %s", backend->prefix, backend->repo_path, name, GIT_REF_SYMBOLIC, symbolic_target);
	}

	if(reply->type == REDIS_REPLY_ERROR) {
		giterr_set_str(GITERR_REFERENCE, "Redis refdb storage error");
		error = GIT_ERROR;
	}

	freeReplyObject(reply);
	return error;
}

int hiredis_refdb_backend__rename(git_reference **out, git_refdb_backend *_backend, const char *old_name,
	const char *new_name, int force, const git_signature *who, const char *message)
{
	hiredis_refdb_backend *backend;
	int error = GIT_OK;
	redisReply *reply;

	assert(old_name && new_name && _backend);

	backend = (hiredis_refdb_backend *) _backend;

	reply = redisCommand(backend->db, "RENAME %s:%s:refdb:%s %s:%s:refdb:%s",
						backend->prefix, backend->repo_path, old_name, backend->prefix, backend->repo_path, new_name);
	if(reply->type == REDIS_REPLY_ERROR) {
		freeReplyObject(reply);

		giterr_set_str(GITERR_REFERENCE, "Redis refdb storage error");
		return GIT_ERROR;
	}

	freeReplyObject(reply);
	return hiredis_refdb_backend__lookup(out, _backend, new_name);
}

int hiredis_refdb_backend__del(git_refdb_backend *_backend, const char *ref_name, const git_oid *old, const char *old_target)
{
	hiredis_refdb_backend *backend;
	int error = GIT_OK;
	redisReply *reply;

	assert(ref_name && _backend);

	backend = (hiredis_refdb_backend *) _backend;

	reply = redisCommand(backend->db, "DEL %s:%s:refdb:%s", backend->prefix, backend->repo_path, ref_name);
	if(reply->type == REDIS_REPLY_ERROR) {
		giterr_set_str(GITERR_REFERENCE, "Redis refdb storage error");
		error = GIT_ERROR;
	}

	freeReplyObject(reply);
	return error;
}

void hiredis_refdb_backend__free(git_refdb_backend *_backend)
{
	hiredis_refdb_backend *backend;

	assert(_backend);
	backend = (hiredis_refdb_backend *) _backend;

	free(backend->repo_path);
	free(backend->prefix);

	redisFree(backend->db);

	free(backend);
}

/* reflog methods */

int hiredis_refdb_backend__has_log(git_refdb_backend *_backend, const char *refname)
{
	return 0;
}

int hiredis_refdb_backend__ensure_log(git_refdb_backend *_backend, const char *refname)
{
	return GIT_ERROR;
}

int hiredis_refdb_backend__reflog_read(git_reflog **out, git_refdb_backend *_backend, const char *name)
{
	return GIT_ERROR;
}

int hiredis_refdb_backend__reflog_write(git_refdb_backend *_backend, git_reflog *reflog)
{
	return GIT_ERROR;
}

int hiredis_refdb_backend__reflog_rename(git_refdb_backend *_backend, const char *old_name, const char *new_name)
{
	return GIT_ERROR;
}

int hiredis_refdb_backend__reflog_delete(git_refdb_backend *_backend, const char *name)
{
	return GIT_ERROR;
}

/* Constructors */

int git_odb_backend_hiredis(git_odb_backend **backend_out, const char* prefix, const char* path, const char *host, int port, char* password)
{
	hiredis_odb_backend *backend;
	redisReply *reply;

	backend = calloc(1, sizeof (hiredis_odb_backend));
	if (backend == NULL)
		return GITERR_NOMEMORY;

	if (sharedConnection == NULL) {
		sharedConnection = redisConnect(host, port);
		if (sharedConnection->err) {
			free(backend);
			giterr_set_str(GITERR_REFERENCE, "Redis odb storage couldn't connect to redis server");
			return GIT_ERROR;
		}

		if(password != NULL) {
			reply = redisCommand(sharedConnection, "AUTH %s", password);
			if (reply->type == REDIS_REPLY_ERROR) {
				giterr_set_str(GITERR_REFERENCE, "Redis odb storage authentication with redis server failed");
				return GIT_ERROR;
			}
			freeReplyObject(reply);
		}
	}

	backend->db = sharedConnection;

	backend->prefix = strdup(prefix);
	backend->repo_path = strdup(path);

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

int git_refdb_backend_hiredis(git_refdb_backend **backend_out, const char* prefix, const char* path, const char *host, int port, char* password)
{
	hiredis_refdb_backend *backend;
	redisReply *reply;

	backend = calloc(1, sizeof(hiredis_refdb_backend));
	if (backend == NULL)
		return GITERR_NOMEMORY;

	if (sharedConnection == NULL) {
		sharedConnection = redisConnect(host, port);
		if (sharedConnection->err) {
			free(backend);
			giterr_set_str(GITERR_REFERENCE, "Redis refdb storage couldn't connect to redis server");
			return GIT_ERROR;
		}

		if(password != NULL) {
			reply = redisCommand(sharedConnection, "AUTH %s", password);
			if (reply->type == REDIS_REPLY_ERROR) {
				giterr_set_str(GITERR_REFERENCE, "Redis refdb storage authentication with redis server failed");
				return GIT_ERROR;
			}
			freeReplyObject(reply);
		}
	}

	backend->db = sharedConnection;

	backend->prefix = strdup(prefix);
	backend->repo_path = strdup(path);

	backend->parent.exists = &hiredis_refdb_backend__exists;
	backend->parent.lookup = &hiredis_refdb_backend__lookup;
	backend->parent.iterator = &hiredis_refdb_backend__iterator;
	backend->parent.write = &hiredis_refdb_backend__write;
	backend->parent.del = &hiredis_refdb_backend__del;
	backend->parent.rename = &hiredis_refdb_backend__rename;
	backend->parent.compress = NULL;
	backend->parent.free = &hiredis_refdb_backend__free;

	backend->parent.has_log = &hiredis_refdb_backend__has_log;
	backend->parent.ensure_log = &hiredis_refdb_backend__ensure_log;
	backend->parent.reflog_read = &hiredis_refdb_backend__reflog_read;
	backend->parent.reflog_write = &hiredis_refdb_backend__reflog_write;
	backend->parent.reflog_rename = &hiredis_refdb_backend__reflog_rename;
	backend->parent.reflog_delete = &hiredis_refdb_backend__reflog_delete;

	*backend_out = (git_refdb_backend *) backend;

	return GIT_OK;
}

