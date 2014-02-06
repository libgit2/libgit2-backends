
#include <assert.h>
#include <string.h>
#include <git2.h>
#include <git2/tag.h>
#include <git2/buffer.h>
#include <git2/object.h>
#include <git2/refdb.h>
#include <git2/errors.h>
#include <git2/sys/refdb_backend.h>
#include <git2/sys/refs.h>
#include <git2/sys/reflog.h>
#include <refs.h>
#include <iterator.h>
#include <refdb.h>
#include <fnmatch.h>
#include <pool.h>
#include <buffer.h>
#include <sqlite3.h>

#define GIT2_REFDB_TABLE_NAME "git2_refdb"
#define GIT_SYMREF "ref: "

typedef struct sqlite_refdb_backend {
  git_refdb_backend parent;
  git_repository *repo;
  sqlite3 *db;
  sqlite3_stmt *st_read;
  sqlite3_stmt *st_read_all;
  sqlite3_stmt *st_write;
  sqlite3_stmt *st_delete;
} sqlite_refdb_backend;

static int ref_error_notfound(const char *name)
{
  giterr_set(GITERR_REFERENCE, "Reference not found: %s", name);
  return GIT_ENOTFOUND;
}

static const char *parse_symbolic(git_buf *ref_content)
{
  const unsigned int header_len = (unsigned int)strlen(GIT_SYMREF);
  const char *refname_start;

  refname_start = (const char *)git_buf_cstr(ref_content);

  if (git_buf_len(ref_content) < header_len + 1) {
    giterr_set(GITERR_REFERENCE, "Corrupted reference");
    return NULL;
  }

  /*
   * Assume we have already checked for the header
   * before calling this function
   */
  refname_start += header_len;

  return refname_start;
}

static int parse_oid(git_oid *oid, const char *filename, git_buf *ref_content)
{
  const char *str = git_buf_cstr(ref_content);

  if (git_buf_len(ref_content) < GIT_OID_HEXSZ)
    goto corrupted;

  /* we need to get 40 OID characters from the file */
  if (git_oid_fromstr(oid, str) < 0)
    goto corrupted;

  /* If the file is longer than 40 chars, the 41st must be a space */
  str += GIT_OID_HEXSZ;
  if (*str == '\0' || git__isspace(*str))
    return 0;

corrupted:
  giterr_set(GITERR_REFERENCE, "Corrupted reference");
  return -1;
}

static int sqlite_refdb_backend__exists(
  int *exists,
  git_refdb_backend *_backend,
  const char *ref_name)
{
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;

  assert(backend);

  *exists = 0;

  if (sqlite3_bind_text(backend->st_read, 1, (char *)ref_name, -1, SQLITE_TRANSIENT) == SQLITE_OK) {
    if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
      *exists = 1;
      assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
    }
  }

  sqlite3_reset(backend->st_read);
  return 0;
}

static int loose_lookup(
  git_reference **out,
  sqlite_refdb_backend *backend,
  const char *ref_name)
{
  git_buf ref_buf = GIT_BUF_INIT;
  int error = SQLITE_ERROR;

  if (sqlite3_bind_text(backend->st_read, 1, (char *)ref_name, -1, SQLITE_TRANSIENT) == SQLITE_OK) {
    if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
      char *raw_ref = (char *)sqlite3_column_text(backend->st_read, 0);

      git_buf_set(&ref_buf, raw_ref, strlen(raw_ref));

      if (git__prefixcmp(git_buf_cstr(&ref_buf), GIT_SYMREF) == 0) {
        const char *target;

        git_buf_rtrim(&ref_buf);

        if (!(target = parse_symbolic(&ref_buf)))
          error = -1;
        else if (out != NULL)
          *out = git_reference__alloc_symbolic(ref_name, target);
      } else {
        git_oid oid;

        if (!(error = parse_oid(&oid, ref_name, &ref_buf)) && out != NULL)
          *out = git_reference__alloc(ref_name, &oid, NULL);
      }

      assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
    } else {
      error = ref_error_notfound(ref_name);
    }
  } else {
    error = ref_error_notfound(ref_name);
  }

  git_buf_free(&ref_buf);
  sqlite3_reset(backend->st_read);

  return error;
}

static int sqlite_refdb_backend__lookup(
  git_reference **out,
  git_refdb_backend *_backend,
  const char *ref_name)
{
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;
  int error;

  assert(backend);

  if (!(error = loose_lookup(out, backend, ref_name)))
    return 0;

  return error;
}

typedef struct {
  git_reference_iterator parent;

  char *glob;

  git_pool pool;
  git_vector loose;

  size_t loose_pos;
} sqlite_refdb_iter;

static void sqlite_refdb_backend__iterator_free(git_reference_iterator *_iter)
{
  sqlite_refdb_iter *iter = (sqlite_refdb_iter *) _iter;

  git_vector_free(&iter->loose);
  git_pool_clear(&iter->pool);
  git__free(iter);
}

static int iter_load_loose_paths(sqlite_refdb_backend *backend, sqlite_refdb_iter *iter)
{
  int error = SQLITE_ERROR;

  while ((error = sqlite3_step(backend->st_read_all)) && (error == SQLITE_ROW)) {
    char *ref_dup;
    char *ref_name = (char *)sqlite3_column_text(backend->st_read_all, 0);

    if (git__suffixcmp(ref_name, ".lock") == 0 ||
      (iter->glob && p_fnmatch(iter->glob, ref_name, 0) != 0))
      continue;

    ref_dup = git_pool_strdup(&iter->pool, ref_name);
    if (!ref_dup)
      error = -1;
    else
      error = git_vector_insert(&iter->loose, ref_dup);
  }

  sqlite3_reset(backend->st_read_all);

  return error;
}

static int sqlite_refdb_backend__iterator_next(
  git_reference **out, git_reference_iterator *_iter)
{
  int error = GIT_ITEROVER;
  sqlite_refdb_iter *iter = (sqlite_refdb_iter *)_iter;
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)iter->parent.db->backend;

  while (iter->loose_pos < iter->loose.length) {
    const char *path = git_vector_get(&iter->loose, iter->loose_pos++);

    if (loose_lookup(out, backend, path) == 0)
      return 0;

    giterr_clear();
  }

  return error;
}

static int sqlite_refdb_backend__iterator_next_name(
  const char **out, git_reference_iterator *_iter)
{
  int error = GIT_ITEROVER;
  sqlite_refdb_iter *iter = (sqlite_refdb_iter *)_iter;
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)iter->parent.db->backend;

  while (iter->loose_pos < iter->loose.length) {
    const char *path = git_vector_get(&iter->loose, iter->loose_pos++);

    if (loose_lookup(NULL, backend, path) == 0) {
      *out = path;
      return 0;
    }

    giterr_clear();
  }

  return error;
}

static int sqlite_refdb_backend__iterator(
  git_reference_iterator **out, git_refdb_backend *_backend, const char *glob)
{
  sqlite_refdb_iter *iter;
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;

  assert(backend);

  iter = git__calloc(1, sizeof(sqlite_refdb_iter));
  GITERR_CHECK_ALLOC(iter);

  if (git_pool_init(&iter->pool, 1, 0) < 0 ||
    git_vector_init(&iter->loose, 8, NULL) < 0)
    goto fail;

  if (glob != NULL &&
    (iter->glob = git_pool_strdup(&iter->pool, glob)) == NULL)
    goto fail;

  iter->parent.next = sqlite_refdb_backend__iterator_next;
  iter->parent.next_name = sqlite_refdb_backend__iterator_next_name;
  iter->parent.free = sqlite_refdb_backend__iterator_free;

  if (iter_load_loose_paths(backend, iter) < 0)
    goto fail;

  *out = (git_reference_iterator *)iter;
  return 0;

fail:
  sqlite_refdb_backend__iterator_free((git_reference_iterator *)iter);
  return -1;
}

static int reference_path_available(
  sqlite_refdb_backend *backend,
  const char *new_ref,
  const char* old_ref,
  int force)
{
  if (!force) {
    int exists;

    if (sqlite_refdb_backend__exists(&exists, (git_refdb_backend *)backend, new_ref) < 0)
      return -1;

    if (exists) {
      giterr_set(GITERR_REFERENCE,
        "Failed to write reference '%s': a reference with "
        "that name already exists.", new_ref);
      return GIT_EEXISTS;
    }
  }

  return 0;
}

static int sqlite_refdb_backend__write(
  git_refdb_backend *_backend,
  const git_reference *ref,
  int force,
  const git_signature *who,
  const char *message)
{
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;
  int error;

  assert(backend);

  error = reference_path_available(backend, ref->name, NULL, force);
  if (error < 0)
    return error;

  error = SQLITE_ERROR;

  if (sqlite3_bind_text(backend->st_write, 1, (char *)ref->name, -1, SQLITE_TRANSIENT) == SQLITE_OK) {
      if (ref->type == GIT_REF_OID) {
      char oid[GIT_OID_HEXSZ + 1];
      git_oid_nfmt(oid, sizeof(oid), &ref->target.oid);

      error = sqlite3_bind_text(backend->st_write, 2, (char *)oid, -1, SQLITE_TRANSIENT);
    } else if (ref->type == GIT_REF_SYMBOLIC) {
      char *symbolic_ref = malloc(strlen(GIT_SYMREF)+strlen(ref->target.symbolic)+1);

      strcpy(symbolic_ref, GIT_SYMREF);
      strcat(symbolic_ref, ref->target.symbolic);
      error = sqlite3_bind_text(backend->st_write, 2, (char *)symbolic_ref, -1, SQLITE_TRANSIENT);
    }

    if (error == SQLITE_OK)
      error = sqlite3_step(backend->st_write);
  }

  sqlite3_reset(backend->st_write);
  if (error == SQLITE_DONE) {
    return GIT_OK;
  } else {
    giterr_set(GITERR_ODB, "Error writing reference to Sqlite RefDB backend");
    return GIT_ERROR;
  }
}

static int sqlite_refdb_backend__delete(git_refdb_backend *_backend, const char *name)
{
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;
  int error;

  assert(backend && name);

  error = SQLITE_ERROR;

  if (sqlite3_bind_text(backend->st_delete, 1, (char *)name, -1, SQLITE_TRANSIENT) == SQLITE_OK) {
    error = sqlite3_step(backend->st_delete);
  }

  sqlite3_reset(backend->st_delete);
  if (error == SQLITE_DONE) {
    return GIT_OK;
  } else {
    giterr_set(GITERR_ODB, "Error deleting reference from Sqlite RefDB backend");
    return GIT_ERROR;
  }
}

static int sqlite_refdb_backend__rename(
  git_reference **out,
  git_refdb_backend *_backend,
  const char *old_name,
  const char *new_name,
  int force,
  const git_signature *who,
  const char *message)
{
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;
  git_reference *old, *new;
  int error;

  assert(backend);

  if ((error = reference_path_available(
      backend, new_name, old_name, force)) < 0 ||
    (error = sqlite_refdb_backend__lookup(&old, _backend, old_name)) < 0)
    return error;

  if ((error = sqlite_refdb_backend__delete(_backend, old_name)) < 0) {
    git_reference_free(old);
    return error;
  }

  new = git_reference__set_name(old, new_name);
  if (!new) {
    git_reference_free(old);
    return -1;
  }

  if ((error = sqlite_refdb_backend__write(_backend, new, force, who, message)) > 0) {
    git_reference_free(new);
    return error;
  }

  *out = new;
  return GIT_OK;
}

static int sqlite_refdb_backend__compress(git_refdb_backend *_backend)
{
  return 0;
}

static int sqlite_refdb_backend__has_log(git_refdb_backend *_backend, const char *name)
{
  return -1;
}

static int sqlite_refdb_backend__ensure_log(git_refdb_backend *_backend, const char *name)
{
  return 0;
}

static void sqlite_refdb_backend__free(git_refdb_backend *_backend)
{
  sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;

  assert(backend);

  sqlite3_finalize(backend->st_read);
  sqlite3_finalize(backend->st_read_all);
  sqlite3_finalize(backend->st_write);
  sqlite3_finalize(backend->st_delete);
  sqlite3_close(backend->db);

  free(backend);
}

static int sqlite_refdb_backend__reflog_read(git_reflog **out, git_refdb_backend *_backend, const char *name)
{
  return 0;
}

static int sqlite_refdb_backend__reflog_write(git_refdb_backend *_backend, git_reflog *reflog)
{
  return 0;
}

static int sqlite_refdb_backend__reflog_rename(git_refdb_backend *_backend, const char *old_name, const char *new_name)
{
  return 0;
}

static int sqlite_refdb_backend__reflog_delete(git_refdb_backend *_backend, const char *name)
{
  return 0;
}

static int create_table(sqlite3 *db)
{
  static const char *sql_creat =
    "CREATE TABLE '" GIT2_REFDB_TABLE_NAME "' ("
    "'refname' TEXT PRIMARY KEY NOT NULL,"
    "'ref' TEXT NOT NULL);";

  if (sqlite3_exec(db, sql_creat, NULL, NULL, NULL) != SQLITE_OK)
    giterr_set(GITERR_REFERENCE, "Error creating table for Sqlite RefDB backend");
    return GIT_ERROR;

  return GIT_OK;
}

static int init_db(sqlite3 *db)
{
  static const char *sql_check =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='" GIT2_REFDB_TABLE_NAME "';";

  sqlite3_stmt *st_check;
  int error;

  if (sqlite3_prepare_v2(db, sql_check, -1, &st_check, NULL) != SQLITE_OK)
    return GIT_ERROR;

  switch (sqlite3_step(st_check)) {
  case SQLITE_DONE:
    /* the table was not found */
    error = create_table(db);
    break;

  case SQLITE_ROW:
    /* the table was found */
    error = GIT_OK;
    break;

  default:
    error = GIT_ERROR;
    break;
  }

  sqlite3_finalize(st_check);
  return error;
}

static int init_statements(sqlite_refdb_backend *backend)
{
  static const char *sql_read =
    "SELECT ref FROM '" GIT2_REFDB_TABLE_NAME "' WHERE refname = ?;";

  static const char *sql_read_all =
    "SELECT refname FROM '" GIT2_REFDB_TABLE_NAME "';";

  static const char *sql_write =
    "INSERT OR IGNORE INTO '" GIT2_REFDB_TABLE_NAME "' VALUES (?, ?);";

  static const char *sql_delete =
    "DELETE FROM '" GIT2_REFDB_TABLE_NAME "' WHERE refname = ?;";

  if (sqlite3_prepare_v2(backend->db, sql_read, -1, &backend->st_read, NULL) != SQLITE_OK) {
    giterr_set(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
    return GIT_ERROR;
  }

  if (sqlite3_prepare_v2(backend->db, sql_read_all, -1, &backend->st_read_all, NULL) != SQLITE_OK) {
    giterr_set(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
    return GIT_ERROR;
  }

  if (sqlite3_prepare_v2(backend->db, sql_write, -1, &backend->st_write, NULL) != SQLITE_OK) {
    giterr_set(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
    return GIT_ERROR;
  }

  if (sqlite3_prepare_v2(backend->db, sql_delete, -1, &backend->st_delete, NULL) != SQLITE_OK) {
    giterr_set(GITERR_REFERENCE, "Error creating prepared statement for Sqlite RefDB backend");
    return GIT_ERROR;
  }

  return GIT_OK;
}

int git_refdb_backend_sqlite(
  git_refdb_backend **backend_out,
  git_repository *repository,
  const char *sqlite_db)
{
  sqlite_refdb_backend *backend;

  backend = calloc(1, sizeof(sqlite_refdb_backend));
  if (backend == NULL)
    return -1;

  backend->repo = repository;

  if (sqlite3_open(sqlite_db, &backend->db) != SQLITE_OK)
    goto fail;

  if (init_db(backend->db) < 0)
    goto fail;

  if (init_statements(backend) < 0)
    goto fail;

  backend->parent.exists = &sqlite_refdb_backend__exists;
  backend->parent.lookup = &sqlite_refdb_backend__lookup;
  backend->parent.iterator = &sqlite_refdb_backend__iterator;
  backend->parent.write = &sqlite_refdb_backend__write;
  backend->parent.del = &sqlite_refdb_backend__delete;
  backend->parent.rename = &sqlite_refdb_backend__rename;
  backend->parent.compress = &sqlite_refdb_backend__compress;
  backend->parent.has_log = &sqlite_refdb_backend__has_log;
  backend->parent.ensure_log = &sqlite_refdb_backend__ensure_log;
  backend->parent.free = &sqlite_refdb_backend__free;
  backend->parent.reflog_read = &sqlite_refdb_backend__reflog_read;
  backend->parent.reflog_write = &sqlite_refdb_backend__reflog_write;
  backend->parent.reflog_rename = &sqlite_refdb_backend__reflog_rename;
  backend->parent.reflog_delete = &sqlite_refdb_backend__reflog_delete;

  *backend_out = (git_refdb_backend *)backend;
  return 0;

fail:
  sqlite_refdb_backend__free((git_refdb_backend *)backend);
  return -1;
}