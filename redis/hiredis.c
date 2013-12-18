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

    redisContext *db;
} hiredis_backend;

int hiredis_backend__read_header(size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
    hiredis_backend *backend;
    int error;
    redisReply *reply;

    assert(len_p && type_p && _backend && oid);

    backend = (hiredis_backend *) _backend;
    error = GIT_ERROR;

    reply = redisCommand(backend->db, "HMGET %b %s %s", oid->id, GIT_OID_RAWSZ,
            "type", "size");

    if (reply && reply->type == REDIS_REPLY_ARRAY) {
        if (reply->element[0]->type != REDIS_REPLY_NIL &&
                reply->element[0]->type != REDIS_REPLY_NIL) {
            *type_p = (git_otype) atoi(reply->element[0]->str);
            *len_p = (size_t) atoi(reply->element[1]->str);
            error = GIT_OK;
        } else {
            error = GIT_ENOTFOUND;
        }
    } else {
        error = GIT_ERROR;
    }

    freeReplyObject(reply);
    return error;
}

int hiredis_backend__read(void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
    hiredis_backend *backend;
    int error;
    redisReply *reply;

    assert(data_p && len_p && type_p && _backend && oid);

    backend = (hiredis_backend *) _backend;
    error = GIT_ERROR;

    reply = redisCommand(backend->db, "HMGET %b %s %s %s", oid->id, GIT_OID_RAWSZ,
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
            error = GIT_ENOTFOUND;
        }
    } else {
        error = GIT_ERROR;
    }

    freeReplyObject(reply);
    return error == GIT_OK;
}

int hiredis_backend__read_prefix(git_oid *out_oid,
		void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend,
		const git_oid *short_oid, unsigned int len)
{
	if (len >= GIT_OID_HEXSZ) {
		/* Just match the full identifier */
		int error = hiredis_backend__read(data_p, len_p, type_p, _backend, short_oid);
		if (error == GIT_OK)
			git_oid_cpy(out_oid, short_oid);

		return error;
	} else if (len < GIT_OID_HEXSZ) {
		/* TODO */
		return GITERR_INVALID;
	}
}

int hiredis_backend__exists(git_odb_backend *_backend, const git_oid *oid)
{
    hiredis_backend *backend;
    int found;
    redisReply *reply;

    assert(_backend && oid);

    backend = (hiredis_backend *) _backend;
    found = 0;

    reply = redisCommand(backend->db, "exists %b", oid->id, GIT_OID_RAWSZ);
    if (reply && reply->type != REDIS_REPLY_NIL && reply->type != REDIS_REPLY_ERROR)
        found = 1;

    freeReplyObject(reply);
    return found;
}

int hiredis_backend__write(git_oid *id, git_odb_backend *_backend, const void *data, size_t len, git_otype type)
{
    hiredis_backend *backend;
    int error;
    redisReply *reply;

    assert(id && _backend && data);

    backend = (hiredis_backend *) _backend;
    error = GIT_ERROR;

    if ((error = git_odb_hash(id, data, len, type)) < 0)
        return error;

    reply = redisCommand(backend->db, "HMSET %b "
            "type %d "
            "size %d "
            "data %b ", id->id, GIT_OID_RAWSZ,
            (int) type, len, data, len);

    error = (reply == NULL || reply->type == REDIS_REPLY_ERROR) ? GIT_ERROR : GIT_OK;

    freeReplyObject(reply);
    return error;
}

void hiredis_backend__free(git_odb_backend *_backend)
{
    hiredis_backend *backend;
    assert(_backend);
    backend = (hiredis_backend *) _backend;

    redisFree(backend->db);

    free(backend);
}

int git_odb_backend_hiredis(git_odb_backend **backend_out, const char *host, int port)
{
    hiredis_backend *backend;

    backend = calloc(1, sizeof (hiredis_backend));
    if (backend == NULL)
        return GITERR_NOMEMORY;

    backend->db = redisConnect(host, port);
    if (backend->db->err) {
		free(backend);
		return GIT_ERROR;
	}

    backend->parent.read = &hiredis_backend__read;
    backend->parent.read_prefix = &hiredis_backend__read_prefix;
    backend->parent.read_header = &hiredis_backend__read_header;
    backend->parent.write = &hiredis_backend__write;
    backend->parent.exists = &hiredis_backend__exists;
    backend->parent.free = &hiredis_backend__free;

    *backend_out = (git_odb_backend *) backend;

    return GIT_OK;
}

