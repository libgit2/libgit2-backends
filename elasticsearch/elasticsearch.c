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

#define GIT2_INDEX_NAME "git2_odb"

typedef struct {
	git_odb_backend parent;
} elasticsearch_backend;

int elasticsearch_backend__read_header(size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid){}

int elasticsearch_backend__read(void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid){}

int elasticsearch_backend__read_prefix(git_oid *out_oid, void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend,
	const git_oid *short_oid, size_t len) {}
	
int elasticsearch_backend__exists(git_odb_backend *_backend, const git_oid *oid){}
	
int elasticsearch_backend__write(git_odb_backend *_backend, const git_oid *id, const void *data, size_t len, git_otype type){}

void elasticsearch_backend__free(git_odb_backend *_backend){}

static int create_index()
{
	int result;
	return result;
}

static int init_db()
{
	int result;
	return result;
}

int git_odb_backend_elasticsearch(git_odb_backend **backend_out)
{
	elasticsearch_backend *backend;
	int result;

	result = init_db();

	if(result == 0)
	{
		backend->parent.version = GIT_ODB_BACKEND_VERSION;
		backend->parent.read = &elasticsearch_backend__read;
		backend->parent.read_prefix = &elasticsearch_backend__read_prefix;
		backend->parent.read_header = &elasticsearch_backend__read_header;
		backend->parent.write = &elasticsearch_backend__write;
		backend->parent.exists = &elasticsearch_backend__exists;
		backend->parent.free = &elasticsearch_backend__free;

		*backend_out = (git_odb_backend *)backend;
	}

	return result;
}
