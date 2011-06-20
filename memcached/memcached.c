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
#include "git2/odb_backend.h"
#include <libmemcached/memcached.h>

typedef struct {
	git_odb_backend parent;
	memcached_st *db;
} memcached_backend;

// Since memcached is just a key/value store, we'll use key suffixes
// to denote the different "fields" we want to store for an object

// the type of object
static const char *type_suffix = ":type";

// store the size so we can know how big an object is
// without needing to fetch the data down
static const char *size_suffix = ":size";

// the raw object data
static const char *data_suffix = ":data";

static char *memcached_backend__build_key(const unsigned char *id, const char *suffix, size_t *out_len)
{
	char *new_key;

	*out_len = 20+strlen(suffix);
	new_key = malloc(*out_len);
	if (!new_key)
		return NULL;

	memcpy(new_key, id, 20);
	memcpy(new_key+20, suffix, strlen(suffix));

	return new_key;
}

int memcached_backend__read_header(size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	memcached_backend *backend;
	memcached_return ret = 0;
	char *type_key, *size_key;
	size_t type_key_len, type_value_len, size_key_len, *size_value, size_value_len;
	uint32_t type_flags, size_flags;
	int status;

	assert(len_p && type_p && _backend && oid);

	backend = (memcached_backend *)_backend;

	type_key = memcached_backend__build_key(oid->id, type_suffix, &type_key_len);
	if (type_key == NULL)
		return GIT_ENOMEM;

	size_key = memcached_backend__build_key(oid->id, size_suffix, &size_key_len);
	if (size_key == NULL)
		return GIT_ENOMEM;


	memset(type_p, 0, sizeof(type_p));
	type_p = (git_otype *)memcached_get(backend->db, type_key, type_key_len, &type_value_len, &type_flags, &ret);
	if (type_p == NULL) {
		status = GIT_ENOTFOUND;
		goto read_header_cleanup;
	}

	memset(size_value, 0, sizeof(size_value));
	memset(len_p, 0, sizeof(len_p));
	size_value = (size_t *)memcached_get(backend->db, size_key, size_key_len, &size_value_len, &size_flags, &ret);
	if (size_value == NULL) {
		if (type_p)
			free(type_p);

		status = GIT_ENOTFOUND;
	} else {
		*len_p = *size_value;
		status = GIT_SUCCESS;
	}

read_header_cleanup:
	free(type_key);
	free(size_key);
	return status;
}

int memcached_backend__read(void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	memcached_backend *backend;
	memcached_return ret = 0;
	char *type_key, *data_key;
	size_t type_key_len, data_key_len, type_value_len;
	uint32_t type_flags, data_flags;
	int status;
	void *type_buffer, *data_buffer;

	assert(data_p && len_p && type_p && _backend && oid);

	backend = (memcached_backend *)_backend;

	type_key = memcached_backend__build_key(oid->id, type_suffix, &type_key_len);
	if (type_key == NULL)
		return GIT_ENOMEM;

	data_key = memcached_backend__build_key(oid->id, data_suffix, &data_key_len);
	if (data_key == NULL)
		return GIT_ENOMEM;


	type_buffer = (void *)memcached_get(backend->db, type_key, type_key_len, &type_value_len, &type_flags, &ret);
	if (type_buffer == NULL) {
		status = GIT_ENOTFOUND;
		goto read_cleanup;
	}

	data_buffer = (void *)memcached_get(backend->db, data_key, data_key_len, len_p, &data_flags, &ret);
	if (data_buffer == NULL && *len_p > 0) {

		if (type_buffer)
			free(type_buffer);

		status = GIT_ENOTFOUND;
	} else {
		*type_p = *(git_otype *)type_buffer;
		free(type_buffer);

		*data_p = data_buffer;
		status = GIT_SUCCESS;
	}

read_cleanup:
	free(type_key);
	free(data_key);
	return status;
}

int memcached_backend__exists(git_odb_backend *_backend, const git_oid *oid)
{
	memcached_backend *backend;
	memcached_return ret = 0;
	int found;
	char *type_key;
	size_t type_key_len;

	assert(_backend && oid);

	backend = (memcached_backend *)_backend;
	found = 0;

	type_key = memcached_backend__build_key(oid->id, type_suffix, &type_key_len);
	if (type_key == NULL)
		return GIT_ENOMEM;

	// use the ADD command with a value of zero length to check for the existence of a key
	// this is because it will let us know if the key already exists
	// and do nothing in that case.
	// we use SET for storing the object so this zero-length value will be overwritten
	// by the actual value we want to store
	ret = memcached_add(backend->db, type_key, type_key_len, "", 0, 0, 0);
	if (ret == MEMCACHED_DATA_EXISTS) {
		// object exists
		found = 1;
	}

	free(type_key);
	return found;
}

int memcached_backend__write(git_oid *oid, git_odb_backend *_backend, const void *data, size_t len, git_otype type)
{
	memcached_backend *backend;
	memcached_return ret = 0;
	char *type_key, *size_key, *data_key;
	size_t type_key_len, size_key_len, data_key_len;
	int status;

	assert(oid && _backend && data);

	backend = (memcached_backend *)_backend;

	if ((status = git_odb_hash(oid, data, len, type)) < 0)
		return status;

	type_key = memcached_backend__build_key(oid->id, type_suffix, &type_key_len);
	if (type_key == NULL)
		return GIT_ENOMEM;

	size_key = memcached_backend__build_key(oid->id, size_suffix, &size_key_len);
	if (size_key == NULL)
		return GIT_ENOMEM;

	data_key = memcached_backend__build_key(oid->id, data_suffix, &data_key_len);
	if (data_key == NULL)
		return GIT_ENOMEM;


	ret = memcached_set(backend->db, type_key, type_key_len, (const char *)&type, sizeof(type), 0, 0);
	if (ret != MEMCACHED_SUCCESS) {
		status = GIT_ERROR;
		goto write_cleanup;
	}

	ret = memcached_set(backend->db, size_key, size_key_len, (const char *)&len, sizeof(len), 0, 0);
	if (ret != MEMCACHED_SUCCESS) {
		status = GIT_ERROR;
		goto write_cleanup;
	}

	ret = memcached_set(backend->db, data_key, data_key_len, (const char *)data, len, 0, 0);
	if (ret != MEMCACHED_SUCCESS) {
		status = GIT_ERROR;
		goto write_cleanup;
	}

	status = GIT_SUCCESS;

write_cleanup:
	free(type_key);
	free(size_key);
	free(data_key);
	return status;
}

void memcached_backend__free(git_odb_backend *_backend)
{
	memcached_backend *backend;
	assert(_backend);
	backend = (memcached_backend *) _backend;

	if (backend->db)
		memcached_free(backend->db);

	free(backend);
}

int git_odb_backend_memcached(git_odb_backend **backend_out, const char *host, int port)
{
	memcached_backend *backend;
	memcached_return ret = 0;
	uint64_t set = 1;

	backend = calloc(1, sizeof (memcached_backend));
	if (backend == NULL)
		return GIT_ENOMEM;


	backend->db = memcached_create(NULL);
	if (backend->db == NULL)
		goto cleanup;

	ret = memcached_server_add(backend->db, host, port);
	if (ret != MEMCACHED_SUCCESS)
		goto cleanup;

	// requires memcached 1.3+
	memcached_behavior_set(backend->db, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, set);

	memcached_behavior_set(backend->db, MEMCACHED_BEHAVIOR_NO_BLOCK, set);
	memcached_behavior_set(backend->db, MEMCACHED_BEHAVIOR_TCP_NODELAY, set);

	backend->parent.read = &memcached_backend__read;
	backend->parent.read_header = &memcached_backend__read_header;
	backend->parent.write = &memcached_backend__write;
	backend->parent.exists = &memcached_backend__exists;
	backend->parent.free = &memcached_backend__free;

	*backend_out = (git_odb_backend *) backend;

	return GIT_SUCCESS;

cleanup:
	free(backend);
	return GIT_ERROR;
}
