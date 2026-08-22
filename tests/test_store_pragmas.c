/*
 * test_store_pragmas.c — Tests for SQLite pragma resolution.
 *
 * Validates that the CBM_SQLITE_MMAP_SIZE env var controls the mmap_size
 * pragma applied to on-disk stores. Default behavior (env unset) must
 * remain 64 MB. Setting the env to 0 disables memory-mapped I/O so
 * concurrent processes that truncate the DB file under a sibling's live
 * mapping return SQLITE_IOERR instead of crashing the process with SIGBUS.
 */
#include "../src/foundation/compat.h"
#include "../src/foundation/compat_fs.h"
#include "../src/foundation/platform.h"
#include "test_framework.h"
#include "test_helpers.h"
#include <store/store.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void clear_mmap_env(void) {
    cbm_unsetenv("CBM_SQLITE_MMAP_SIZE");
}

TEST(mmap_size_default_when_unset) {
    clear_mmap_env();
    ASSERT_EQ(cbm_store_resolve_mmap_size(), 67108864LL);
    PASS();
}

TEST(mmap_size_zero_disables_mmap) {
    cbm_setenv("CBM_SQLITE_MMAP_SIZE", "0", 1);
    ASSERT_EQ(cbm_store_resolve_mmap_size(), 0LL);
    clear_mmap_env();
    PASS();
}

TEST(mmap_size_explicit_value) {
    cbm_setenv("CBM_SQLITE_MMAP_SIZE", "1048576", 1);
    ASSERT_EQ(cbm_store_resolve_mmap_size(), 1048576LL);
    clear_mmap_env();
    PASS();
}

TEST(mmap_size_negative_clamped_to_zero) {
    cbm_setenv("CBM_SQLITE_MMAP_SIZE", "-1", 1);
    ASSERT_EQ(cbm_store_resolve_mmap_size(), 0LL);
    clear_mmap_env();
    PASS();
}

TEST(mmap_size_garbage_falls_back_to_default) {
    cbm_setenv("CBM_SQLITE_MMAP_SIZE", "not-a-number", 1);
    ASSERT_EQ(cbm_store_resolve_mmap_size(), 67108864LL);
    clear_mmap_env();
    PASS();
}

TEST(mmap_size_partial_garbage_falls_back_to_default) {
    cbm_setenv("CBM_SQLITE_MMAP_SIZE", "123abc", 1);
    ASSERT_EQ(cbm_store_resolve_mmap_size(), 67108864LL);
    clear_mmap_env();
    PASS();
}

/* Integration smoke: opening a file-backed store with mmap_size=0 must
 * succeed. Proves the resolver is wired through configure_pragmas(). */
TEST(store_open_with_mmap_disabled) {
    cbm_setenv("CBM_SQLITE_MMAP_SIZE", "0", 1);
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s/cbm_test_pragmas_%d.db", cbm_tmpdir(), (int)getpid());
    unlink(tmp_path);

    cbm_store_t *s = cbm_store_open_path(tmp_path);
    ASSERT(s != NULL);
    cbm_store_close(s);

    unlink(tmp_path);
    /* WAL/SHM siblings created by the open */
    char tmp_wal[300];
    char tmp_shm[300];
    snprintf(tmp_wal, sizeof(tmp_wal), "%s-wal", tmp_path);
    snprintf(tmp_shm, sizeof(tmp_shm), "%s-shm", tmp_path);
    unlink(tmp_wal);
    unlink(tmp_shm);

    clear_mmap_env();
    PASS();
}

static bool strict_fixture_make_db(const char *path, const char *project,
                                   const char *node_name) {
    cbm_store_t *store = cbm_store_open_path(path);
    if (!store) {
        return false;
    }
    cbm_node_t node = {
        .project = project,
        .label = "Function",
        .name = node_name,
        .qualified_name = node_name,
        .file_path = "probe.c",
        .start_line = 1,
        .end_line = 1,
        .properties_json = "{}",
    };
    bool ok = cbm_store_upsert_project(store, project, "/tmp/strict-probe") ==
                  CBM_STORE_OK &&
              cbm_store_upsert_node(store, &node) > 0 &&
              cbm_store_prepare_for_publish(store) == CBM_STORE_OK;
    cbm_store_close(store);
    return ok;
}

#ifndef _WIN32
TEST(strict_query_rejects_final_symlink_but_accepts_ancestor_alias) {
    char *tmp = th_mktempdir("cbm_strict_symlink");
    ASSERT_NOT_NULL(tmp);
    char real_dir[512];
    char alias_dir[512];
    char real_path[768];
    char alias_path[768];
    char final_link[768];
    snprintf(real_dir, sizeof(real_dir), "%s/real", tmp);
    snprintf(alias_dir, sizeof(alias_dir), "%s/alias", tmp);
    snprintf(real_path, sizeof(real_path), "%s/strict.db", real_dir);
    snprintf(alias_path, sizeof(alias_path), "%s/strict.db", alias_dir);
    snprintf(final_link, sizeof(final_link), "%s/final.db", tmp);

    ASSERT_EQ(mkdir(real_dir, 0700), 0);
    ASSERT_EQ(symlink(real_dir, alias_dir), 0);
    ASSERT_TRUE(strict_fixture_make_db(real_path, "strict-symlink", "StrictSymlink"));

    cbm_store_t *through_alias = cbm_store_open_path_query_strict(alias_path);
    ASSERT_NOT_NULL(through_alias);
    ASSERT_TRUE(cbm_store_strict_snapshot_valid(through_alias));
    cbm_store_close(through_alias);

    ASSERT_EQ(symlink(real_path, final_link), 0);
    ASSERT_NULL(cbm_store_open_path_query_strict(final_link));

    ASSERT_EQ(unlink(final_link), 0);
    ASSERT_EQ(unlink(alias_dir), 0);
    ASSERT_EQ(th_rmtree(tmp), 0);
    PASS();
}
#endif

static unsigned char *strict_fixture_read_bytes(const char *path, size_t *size_out) {
    if (!path || !size_out) {
        return NULL;
    }
    *size_out = 0;
    FILE *file = cbm_fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END) != 0) {
        if (file) {
            fclose(file);
        }
        return NULL;
    }
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    unsigned char *bytes = malloc(size > 0 ? (size_t)size : 1U);
    if (!bytes) {
        fclose(file);
        return NULL;
    }
    size_t got = fread(bytes, 1, (size_t)size, file);
    fclose(file);
    if (got != (size_t)size) {
        free(bytes);
        return NULL;
    }
    *size_out = got;
    return bytes;
}

static bool strict_fixture_sidecars_absent(const char *path) {
    static const char *const suffixes[] = {"-wal", "-shm", "-journal"};
    char sidecar[1024];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(sidecar, sizeof(sidecar), "%s%s", path, suffixes[i]);
        if (n < 0 || (size_t)n >= sizeof(sidecar) ||
            cbm_file_exists(sidecar)) {
            return false;
        }
    }
    return true;
}

static bool strict_fixture_dir_only_contains(const char *dir, const char *expected) {
    cbm_dir_t *entries = cbm_opendir(dir);
    if (!entries) {
        return false;
    }
    int count = 0;
    bool match = true;
    cbm_dirent_t *entry = NULL;
    while ((entry = cbm_readdir(entries)) != NULL) {
        count++;
        match = match && strcmp(entry->name, expected) == 0;
    }
    cbm_closedir(entries);
    return match && count == 1;
}

TEST(strict_query_clean_generation_is_byte_stable) {
    char *tmp = th_mktempdir("cbm_strict_clean");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char path[768];
    snprintf(path, sizeof(path), "%s/strict-clean.db", dir);
    ASSERT_TRUE(strict_fixture_make_db(path, "strict-clean", "StrictProbe"));
    cbm_store_t *legacy = cbm_store_open_path(path);
    ASSERT_NOT_NULL(legacy);
    ASSERT_EQ(sqlite3_exec(cbm_store_get_db(legacy), "DROP TABLE store_meta;", NULL,
                           NULL, NULL),
              SQLITE_OK);
    ASSERT_EQ(cbm_store_prepare_for_publish(legacy), CBM_STORE_OK);
    cbm_store_close(legacy);
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));
    ASSERT_TRUE(strict_fixture_dir_only_contains(dir, "strict-clean.db"));

    size_t before_size = 0;
    unsigned char *before = strict_fixture_read_bytes(path, &before_size);
    ASSERT_NOT_NULL(before);
    struct stat before_stat;
    ASSERT_EQ(stat(path, &before_stat), 0);

    cbm_store_t *strict = cbm_store_open_path_query_strict(path);
    ASSERT_NOT_NULL(strict);
    cbm_project_t project = {0};
    ASSERT_EQ(cbm_store_get_project(strict, "strict-clean", &project), CBM_STORE_OK);
    ASSERT_STR_EQ(project.name, "strict-clean");
    cbm_project_free_fields(&project);
    ASSERT_EQ(cbm_store_count_nodes(strict, "strict-clean"), 1);
    char generation[32];
    ASSERT_EQ(cbm_store_generation(strict, generation, sizeof(generation)),
              CBM_STORE_OK);
    ASSERT_STR_EQ(generation, "legacy");
    sqlite3_stmt *mmap_stmt = NULL;
    ASSERT_EQ(sqlite3_prepare_v2(cbm_store_get_db(strict), "PRAGMA mmap_size;", -1,
                                 &mmap_stmt, NULL),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_step(mmap_stmt), SQLITE_ROW);
    ASSERT_EQ(sqlite3_column_int64(mmap_stmt, 0), 0);
    ASSERT_EQ(sqlite3_finalize(mmap_stmt), SQLITE_OK);
    ASSERT_TRUE(cbm_store_strict_snapshot_valid(strict));
    cbm_store_close(strict);

    size_t after_size = 0;
    unsigned char *after = strict_fixture_read_bytes(path, &after_size);
    ASSERT_NOT_NULL(after);
    struct stat after_stat;
    ASSERT_EQ(stat(path, &after_stat), 0);
    ASSERT_EQ(after_size, before_size);
    ASSERT_EQ(memcmp(before, after, before_size), 0);
    ASSERT_EQ(after_stat.st_size, before_stat.st_size);
    ASSERT_EQ(after_stat.st_mtime, before_stat.st_mtime);
    ASSERT_EQ(after_stat.st_ctime, before_stat.st_ctime);
#ifdef __APPLE__
    ASSERT_EQ(after_stat.st_mtimespec.tv_nsec, before_stat.st_mtimespec.tv_nsec);
    ASSERT_EQ(after_stat.st_ctimespec.tv_nsec, before_stat.st_ctimespec.tv_nsec);
#elif !defined(_WIN32)
    ASSERT_EQ(after_stat.st_mtim.tv_nsec, before_stat.st_mtim.tv_nsec);
    ASSERT_EQ(after_stat.st_ctim.tv_nsec, before_stat.st_ctim.tv_nsec);
#endif
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));
    ASSERT_TRUE(strict_fixture_dir_only_contains(dir, "strict-clean.db"));

    free(before);
    free(after);
    th_rmtree(dir);
    PASS();
}

TEST(strict_query_bfs_temp_tables_are_memory_only) {
    char *tmp = th_mktempdir("cbm_strict_bfs");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char path[768];
    snprintf(path, sizeof(path), "%s/strict-bfs.db", dir);

    cbm_store_t *writer = cbm_store_open_path(path);
    ASSERT_NOT_NULL(writer);
    ASSERT_EQ(cbm_store_upsert_project(writer, "strict-bfs", "/tmp/strict-bfs"),
              CBM_STORE_OK);
    int64_t ids[3];
    for (int i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "BfsProbe%d", i);
        cbm_node_t node = {
            .project = "strict-bfs",
            .label = "Function",
            .name = name,
            .qualified_name = name,
            .file_path = "probe.c",
            .start_line = i + 1,
            .end_line = i + 1,
            .properties_json = "{}",
        };
        ids[i] = cbm_store_upsert_node(writer, &node);
        ASSERT_TRUE(ids[i] > 0);
    }
    cbm_edge_t edges[2] = {
        {.project = "strict-bfs", .source_id = ids[0], .target_id = ids[1], .type = "CALLS"},
        {.project = "strict-bfs", .source_id = ids[1], .target_id = ids[2], .type = "CALLS"},
    };
    ASSERT_EQ(cbm_store_insert_edge_batch(writer, edges, 2), CBM_STORE_OK);
    ASSERT_EQ(cbm_store_prepare_for_publish(writer), CBM_STORE_OK);
    cbm_store_close(writer);
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));
    ASSERT_TRUE(strict_fixture_dir_only_contains(dir, "strict-bfs.db"));

    size_t before_size = 0;
    unsigned char *before = strict_fixture_read_bytes(path, &before_size);
    ASSERT_NOT_NULL(before);
    struct stat before_db;
    struct stat before_dir;
    ASSERT_EQ(stat(path, &before_db), 0);
    ASSERT_EQ(stat(dir, &before_dir), 0);

    cbm_store_t *strict = cbm_store_open_path_query_strict(path);
    ASSERT_NOT_NULL(strict);
    sqlite3_stmt *temp_stmt = NULL;
    ASSERT_EQ(sqlite3_prepare_v2(cbm_store_get_db(strict), "PRAGMA temp_store;", -1,
                                 &temp_stmt, NULL),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_step(temp_stmt), SQLITE_ROW);
    ASSERT_EQ(sqlite3_column_int(temp_stmt, 0), 2);
    ASSERT_EQ(sqlite3_finalize(temp_stmt), SQLITE_OK);

    cbm_traverse_result_t bfs = {0};
    ASSERT_EQ(cbm_store_bfs(strict, ids[0], "outbound", NULL, 0, 3, 10, &bfs),
              CBM_STORE_OK);
    ASSERT_EQ(bfs.visited_count, 2);
    cbm_store_traverse_free(&bfs);

    cbm_traverse_result_t multi = {0};
    bool truncated = true;
    ASSERT_EQ(cbm_store_bfs_multi(strict, ids, 2, "outbound", NULL, 0, 3, 10,
                                  &multi, &truncated),
              CBM_STORE_OK);
    ASSERT_EQ(multi.visited_count, 1);
    ASSERT_FALSE(truncated);
    cbm_store_traverse_free(&multi);
    ASSERT_TRUE(cbm_store_strict_snapshot_valid(strict));
    cbm_store_close(strict);

    size_t after_size = 0;
    unsigned char *after = strict_fixture_read_bytes(path, &after_size);
    ASSERT_NOT_NULL(after);
    struct stat after_db;
    struct stat after_dir;
    ASSERT_EQ(stat(path, &after_db), 0);
    ASSERT_EQ(stat(dir, &after_dir), 0);
    ASSERT_EQ(after_size, before_size);
    ASSERT_EQ(memcmp(after, before, before_size), 0);
    ASSERT_EQ(after_db.st_size, before_db.st_size);
    ASSERT_EQ(after_db.st_mtime, before_db.st_mtime);
    ASSERT_EQ(after_db.st_ctime, before_db.st_ctime);
    ASSERT_EQ(after_dir.st_mtime, before_dir.st_mtime);
    ASSERT_EQ(after_dir.st_ctime, before_dir.st_ctime);
#ifdef __APPLE__
    ASSERT_EQ(after_db.st_mtimespec.tv_nsec, before_db.st_mtimespec.tv_nsec);
    ASSERT_EQ(after_db.st_ctimespec.tv_nsec, before_db.st_ctimespec.tv_nsec);
    ASSERT_EQ(after_dir.st_mtimespec.tv_nsec, before_dir.st_mtimespec.tv_nsec);
    ASSERT_EQ(after_dir.st_ctimespec.tv_nsec, before_dir.st_ctimespec.tv_nsec);
#elif !defined(_WIN32)
    ASSERT_EQ(after_db.st_mtim.tv_nsec, before_db.st_mtim.tv_nsec);
    ASSERT_EQ(after_db.st_ctim.tv_nsec, before_db.st_ctim.tv_nsec);
    ASSERT_EQ(after_dir.st_mtim.tv_nsec, before_dir.st_mtim.tv_nsec);
    ASSERT_EQ(after_dir.st_ctim.tv_nsec, before_dir.st_ctim.tv_nsec);
#endif
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));
    ASSERT_TRUE(strict_fixture_dir_only_contains(dir, "strict-bfs.db"));

    free(after);
    free(before);
    th_rmtree(dir);
    PASS();
}

TEST(strict_query_latches_access_errors) {
    char *tmp = th_mktempdir("cbm_strict_fault");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char path[768];
    snprintf(path, sizeof(path), "%s/strict-fault.db", dir);
    ASSERT_TRUE(strict_fixture_make_db(path, "strict-fault", "StrictFault"));

    cbm_store_t *strict = cbm_store_open_path_query_strict(path);
    ASSERT_NOT_NULL(strict);
    ASSERT_TRUE(cbm_store_strict_snapshot_valid(strict));
    ASSERT_EQ(cbm_store_exec(strict, "SELECT * FROM definitely_missing_table;"),
              CBM_STORE_ERR);
    ASSERT_FALSE(cbm_store_strict_snapshot_valid(strict));
    cbm_store_close(strict);

    th_rmtree(dir);
    PASS();
}

TEST(strict_query_rejects_live_sidecars) {
    char *tmp = th_mktempdir("cbm_strict_sidecar");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char path[768];
    snprintf(path, sizeof(path), "%s/strict-sidecar.db", dir);

    cbm_store_t *writer = cbm_store_open_path(path);
    ASSERT_NOT_NULL(writer);
    ASSERT_EQ(cbm_store_exec(writer, "PRAGMA wal_autocheckpoint=0;"), CBM_STORE_OK);
    ASSERT_EQ(cbm_store_upsert_project(writer, "strict-sidecar", "/tmp/strict-sidecar"),
              CBM_STORE_OK);
    char wal_path[800];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", path);
    ASSERT_TRUE(cbm_file_exists(wal_path));
    ASSERT_NULL(cbm_store_open_path_query_strict(path));
    cbm_store_close(writer);

    writer = cbm_store_open_path(path);
    ASSERT_NOT_NULL(writer);
    ASSERT_EQ(cbm_store_prepare_for_publish(writer), CBM_STORE_OK);
    cbm_store_close(writer);
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));
    char journal_path[800];
    snprintf(journal_path, sizeof(journal_path), "%s-journal", path);
    ASSERT_EQ(th_write_file(journal_path, "active"), 0);
    ASSERT_NULL(cbm_store_open_path_query_strict(path));

    th_rmtree(dir);
    PASS();
}

TEST(strict_query_rejects_persisted_wal_header_without_sidecars) {
    char *tmp = th_mktempdir("cbm_strict_wal_header");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char path[768];
    snprintf(path, sizeof(path), "%s/persisted-wal.db", dir);
    ASSERT_TRUE(strict_fixture_make_db(path, "persisted-wal", "WalHeader"));

    sqlite3 *raw = NULL;
    ASSERT_EQ(sqlite3_open(path, &raw), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(raw,
                           "PRAGMA journal_mode=WAL;"
                           "BEGIN IMMEDIATE;"
                           "UPDATE projects SET indexed_at=indexed_at;"
                           "COMMIT;",
                           NULL, NULL, NULL),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_close(raw), SQLITE_OK);
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));

    size_t byte_count = 0;
    unsigned char *bytes = strict_fixture_read_bytes(path, &byte_count);
    ASSERT_NOT_NULL(bytes);
    ASSERT_TRUE(byte_count > 19);
    ASSERT_EQ(bytes[18], 2);
    ASSERT_EQ(bytes[19], 2);

    struct stat before_db;
    struct stat before_dir;
    ASSERT_EQ(stat(path, &before_db), 0);
    ASSERT_EQ(stat(dir, &before_dir), 0);
    ASSERT_TRUE(strict_fixture_dir_only_contains(dir, "persisted-wal.db"));
    ASSERT_NULL(cbm_store_open_path_query_strict(path));

    size_t after_count = 0;
    unsigned char *after = strict_fixture_read_bytes(path, &after_count);
    ASSERT_NOT_NULL(after);
    struct stat after_db;
    struct stat after_dir;
    ASSERT_EQ(stat(path, &after_db), 0);
    ASSERT_EQ(stat(dir, &after_dir), 0);
    ASSERT_EQ(after_count, byte_count);
    ASSERT_EQ(memcmp(after, bytes, byte_count), 0);
    ASSERT_EQ(after_db.st_size, before_db.st_size);
    ASSERT_EQ(after_db.st_mtime, before_db.st_mtime);
    ASSERT_EQ(after_db.st_ctime, before_db.st_ctime);
    ASSERT_EQ(after_dir.st_mtime, before_dir.st_mtime);
    ASSERT_EQ(after_dir.st_ctime, before_dir.st_ctime);
#ifdef __APPLE__
    ASSERT_EQ(after_db.st_mtimespec.tv_nsec, before_db.st_mtimespec.tv_nsec);
    ASSERT_EQ(after_db.st_ctimespec.tv_nsec, before_db.st_ctimespec.tv_nsec);
    ASSERT_EQ(after_dir.st_mtimespec.tv_nsec, before_dir.st_mtimespec.tv_nsec);
    ASSERT_EQ(after_dir.st_ctimespec.tv_nsec, before_dir.st_ctimespec.tv_nsec);
#elif !defined(_WIN32)
    ASSERT_EQ(after_db.st_mtim.tv_nsec, before_db.st_mtim.tv_nsec);
    ASSERT_EQ(after_db.st_ctim.tv_nsec, before_db.st_ctim.tv_nsec);
    ASSERT_EQ(after_dir.st_mtim.tv_nsec, before_dir.st_mtim.tv_nsec);
    ASSERT_EQ(after_dir.st_ctim.tv_nsec, before_dir.st_ctim.tv_nsec);
#endif
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));
    ASSERT_TRUE(strict_fixture_dir_only_contains(dir, "persisted-wal.db"));

    free(after);
    free(bytes);

    th_rmtree(dir);
    PASS();
}

TEST(strict_query_rejects_malformed_or_schema_invalid_db) {
    char *tmp = th_mktempdir("cbm_strict_bad");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char path[768];
    snprintf(path, sizeof(path), "%s/malformed.db", dir);
    ASSERT_EQ(th_write_file(path, "not a sqlite database"), 0);
    ASSERT_NULL(cbm_store_open_path_query_strict(path));

    snprintf(path, sizeof(path), "%s/empty.db", dir);
    sqlite3 *raw = NULL;
    ASSERT_EQ(sqlite3_open(path, &raw), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(raw, "CREATE TABLE unrelated(value TEXT);", NULL, NULL, NULL),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_close(raw), SQLITE_OK);
    ASSERT_NULL(cbm_store_open_path_query_strict(path));

    snprintf(path, sizeof(path), "%s/projects-lookalike.db", dir);
    raw = NULL;
    ASSERT_EQ(sqlite3_open(path, &raw), SQLITE_OK);
    ASSERT_EQ(sqlite3_exec(raw,
                           "CREATE TABLE projects("
                           "name TEXT PRIMARY KEY,indexed_at TEXT NOT NULL,"
                           "root_path TEXT NOT NULL);"
                           "INSERT INTO projects VALUES("
                           "'projects-lookalike','2026-01-01T00:00:00Z','/tmp/lookalike');",
                           NULL, NULL, NULL),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_close(raw), SQLITE_OK);
    ASSERT_TRUE(strict_fixture_sidecars_absent(path));
    ASSERT_NULL(cbm_store_open_path_query_strict(path));

    th_rmtree(dir);
    PASS();
}

#ifndef _WIN32
TEST(strict_query_rejects_fifo_without_blocking) {
    char *tmp = th_mktempdir("cbm_strict_fifo");
    ASSERT_NOT_NULL(tmp);
    char path[768];
    snprintf(path, sizeof(path), "%s/not-a-database.db", tmp);
    ASSERT_EQ(mkfifo(path, 0600), 0);

    uint64_t started = cbm_now_ms();
    cbm_store_t *store = cbm_store_open_path_query_strict(path);
    uint64_t elapsed = cbm_now_ms() - started;

    ASSERT_NULL(store);
    ASSERT_LT(elapsed, 1000U);
    th_rmtree(tmp);
    PASS();
}
#endif

TEST(strict_query_detects_generation_replacement) {
#ifdef _WIN32
    char *tmp = th_mktempdir("cbm_strict_replace");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char active[768];
    char next[768];
    snprintf(active, sizeof(active), "%s/active.db", dir);
    snprintf(next, sizeof(next), "%s/next.db", dir);
    ASSERT_TRUE(strict_fixture_make_db(active, "active", "GenerationA"));
    ASSERT_TRUE(strict_fixture_make_db(next, "active", "GenerationB"));

    cbm_store_t *strict = cbm_store_open_path_query_strict(active);
    ASSERT_NOT_NULL(strict);
    ASSERT_TRUE(cbm_store_strict_snapshot_valid(strict));
    ASSERT_NEQ(cbm_rename_replace(next, active), 0);
    ASSERT_TRUE(cbm_store_strict_snapshot_valid(strict));
    cbm_store_close(strict);
    ASSERT_EQ(cbm_rename_replace(next, active), 0);

    th_rmtree(dir);
    PASS();
#else
    char *tmp = th_mktempdir("cbm_strict_replace");
    ASSERT_NOT_NULL(tmp);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", tmp);
    char active[768];
    char next[768];
    snprintf(active, sizeof(active), "%s/active.db", dir);
    snprintf(next, sizeof(next), "%s/next.db", dir);
    ASSERT_TRUE(strict_fixture_make_db(active, "active", "GenerationA"));
    ASSERT_TRUE(strict_fixture_make_db(next, "active", "GenerationB"));

    cbm_store_t *strict = cbm_store_open_path_query_strict(active);
    ASSERT_NOT_NULL(strict);
    ASSERT_TRUE(cbm_store_strict_snapshot_valid(strict));
    ASSERT_EQ(cbm_rename_replace(next, active), 0);
    ASSERT_FALSE(cbm_store_strict_snapshot_valid(strict));
    cbm_store_close(strict);

    th_rmtree(dir);
    PASS();
#endif
}

/* #1083: on-disk write connections must bound the WAL via journal_size_limit
 * so a checkpoint-starved log is physically reclaimed once a checkpoint can
 * reset it. On main this is UNSET (-1 = unlimited), so the -wal file only ever
 * grows (all our checkpoints are PASSIVE and never ftruncate). Read the pragma
 * back on the SAME connection — it's per-connection and not persisted. */
TEST(journal_size_limit_bounds_wal_issue1083) {
    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s/cbm_test_jsl_%d.db", cbm_tmpdir(), (int)getpid());
    unlink(tmp_path);

    cbm_store_t *s = cbm_store_open_path(tmp_path);
    ASSERT(s != NULL);
    /* 256 MiB — far above the healthy WAL (~4 MiB), so no truncate/regrow churn
     * in normal operation; it only fires after abnormal (starved) growth. */
    ASSERT(cbm_store_journal_size_limit(s) == (int64_t)268435456);
    cbm_store_close(s);

    unlink(tmp_path);
    char tmp_wal[300];
    char tmp_shm[300];
    snprintf(tmp_wal, sizeof(tmp_wal), "%s-wal", tmp_path);
    snprintf(tmp_shm, sizeof(tmp_shm), "%s-shm", tmp_path);
    unlink(tmp_wal);
    unlink(tmp_shm);
    PASS();
}

/* Pagination-cursor generation: minted per DB file, bumped per index run.
 * Same store + reads only -> stable; upsert_project (every index run's choke
 * point) -> changes; two distinct DB files can never share a generation even
 * at the same counter value (random db_uid). */
TEST(store_generation_tracks_mutations) {
    char g1[128];
    char g2[128];
    char g3[128];
    cbm_store_t *a = cbm_store_open_memory();
    ASSERT(a != NULL);
    ASSERT_EQ(cbm_store_upsert_project(a, "p", "/tmp/p"), CBM_STORE_OK);
    ASSERT_EQ(cbm_store_generation(a, g1, sizeof(g1)), CBM_STORE_OK);
    ASSERT(strncmp(g1, "u", 1) == 0); /* seeded, not legacy */
    ASSERT_EQ(cbm_store_generation(a, g2, sizeof(g2)), CBM_STORE_OK);
    ASSERT(strcmp(g1, g2) == 0); /* reads are stable */
    ASSERT_EQ(cbm_store_upsert_project(a, "p", "/tmp/p"), CBM_STORE_OK);
    ASSERT_EQ(cbm_store_generation(a, g3, sizeof(g3)), CBM_STORE_OK);
    ASSERT(strcmp(g1, g3) != 0); /* index run bumps */

    cbm_store_t *b = cbm_store_open_memory();
    ASSERT(b != NULL);
    ASSERT_EQ(cbm_store_upsert_project(b, "p", "/tmp/p"), CBM_STORE_OK);
    char gb[128];
    ASSERT_EQ(cbm_store_generation(b, gb, sizeof(gb)), CBM_STORE_OK);
    ASSERT(strcmp(g1, gb) != 0); /* distinct DBs never alias (random uid) */
    cbm_store_close(a);
    cbm_store_close(b);
    PASS();
}

/* #896: a row-scan that dies mid-stream (SQLITE_CORRUPT) must surface a
 * loud store error, not masquerade as a clean end of results. Counts are
 * answered from covering indexes (still correct) while row fetches die at
 * the first corrupt table page — the old loops discarded the terminal
 * sqlite3_step code, so every query surface returned plausible
 * truncated/empty answers with no error. */
TEST(corrupt_page_scan_returns_error_not_truncation) {
    enum { CORRUPT_NODES = 2000, ZERO_PAGES = 40 };
    char *td = th_mktempdir("cbm_corrupt");
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/c.db", td);

    cbm_store_t *s = cbm_store_open_path(db_path);
    ASSERT_NOT_NULL(s);
    cbm_store_upsert_project(s, "corr", "/tmp/corr");
    for (int i = 0; i < CORRUPT_NODES; i++) {
        char name[64];
        char qn[256];
        snprintf(name, sizeof(name), "corrupt_probe_fn_%04d", i);
        snprintf(qn, sizeof(qn),
                 "corr.some.rather.long.module.path.to.fill.table.pages.%s_padding_padding", name);
        cbm_node_t n = {.project = "corr",
                        .label = "Function",
                        .name = name,
                        .qualified_name = qn,
                        .file_path = "src/corrupt_probe.py",
                        .start_line = i + 1,
                        .end_line = i + 2};
        ASSERT_TRUE(cbm_store_upsert_node(s, &n) > 0);
    }
    /* Precondition: a full scan works on the healthy file. */
    cbm_search_params_t params = {.project = "corr", .label = "Function", .limit = 50};
    cbm_search_output_t out = {0};
    ASSERT_EQ(cbm_store_search(s, &params, &out), CBM_STORE_OK);
    ASSERT_EQ(out.total, CORRUPT_NODES);
    cbm_store_search_free(&out);
    cbm_store_close(s);

    /* Zero a band of mid-file pages (the report's dd repro): page 25%..
     * covers nodes-table leaves on a file this shape. */
    FILE *f = fopen(db_path, "rb+");
    ASSERT_NOT_NULL(f);
    (void)fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    enum { PAGE = 4096 };
    long page_count = fsize / PAGE;
    ASSERT_TRUE(page_count > ZERO_PAGES + 8);
    char zero[PAGE];
    memset(zero, 0, sizeof(zero));
    (void)fseek(f, (page_count / 4) * (long)PAGE, SEEK_SET);
    for (int i = 0; i < ZERO_PAGES; i++) {
        ASSERT_EQ(fwrite(zero, 1, PAGE, f), (size_t)PAGE);
    }
    (void)fclose(f);

    /* The scans must now fail LOUDLY (CBM_STORE_ERR), not truncate. */
    cbm_store_t *s2 = cbm_store_open_path(db_path);
    ASSERT_NOT_NULL(s2);
    /* The scan must CROSS the corrupt band: request every row. */
    cbm_search_params_t all_params = {
        .project = "corr", .label = "Function", .limit = CORRUPT_NODES};
    cbm_search_output_t out2 = {0};
    int rc_search = cbm_store_search(s2, &all_params, &out2);
    if (rc_search == CBM_STORE_OK && out2.count == CORRUPT_NODES) {
        /* Vacuous-guard: a complete, healthy scan means corruption missed
         * the table pages — rebuild the fixture, don't relax the assert. */
        FAIL("fixture failed to hit table pages (full scan healthy)");
    }
    /* THE BUG (#896): OK + silently truncated rows. Fixed = loud ERR. */
    ASSERT_EQ(rc_search, CBM_STORE_ERR);
    cbm_store_search_free(&out2);

    /* Point lookups may legitimately succeed when their row's page
     * escaped the corrupt band — the class contract is about SCANS. A
     * second scan surface (qn-suffix, different SQL path) must also err. */
    cbm_node_t *hits = NULL;
    int hit_count = 0;
    int rc_suffix =
        cbm_store_find_nodes_by_qn_suffix(s2, "corr", "padding_padding", &hits, &hit_count);
    if (rc_suffix == CBM_STORE_OK && hit_count == CORRUPT_NODES) {
        FAIL("suffix scan healthy — fixture failed to hit table pages");
    }
    ASSERT_EQ(rc_suffix, CBM_STORE_ERR);
    cbm_store_free_nodes(hits, hit_count);
    cbm_store_close(s2);

    unlink(db_path);
    PASS();
}

SUITE(store_pragmas) {
#ifndef _WIN32
    RUN_TEST(strict_query_rejects_final_symlink_but_accepts_ancestor_alias);
#endif
    RUN_TEST(strict_query_clean_generation_is_byte_stable);
    RUN_TEST(strict_query_bfs_temp_tables_are_memory_only);
    RUN_TEST(strict_query_latches_access_errors);
    RUN_TEST(strict_query_rejects_live_sidecars);
    RUN_TEST(strict_query_rejects_persisted_wal_header_without_sidecars);
    RUN_TEST(strict_query_rejects_malformed_or_schema_invalid_db);
#ifndef _WIN32
    RUN_TEST(strict_query_rejects_fifo_without_blocking);
#endif
    RUN_TEST(strict_query_detects_generation_replacement);
    RUN_TEST(journal_size_limit_bounds_wal_issue1083);
    RUN_TEST(store_generation_tracks_mutations);
    RUN_TEST(corrupt_page_scan_returns_error_not_truncation);
    RUN_TEST(mmap_size_default_when_unset);
    RUN_TEST(mmap_size_zero_disables_mmap);
    RUN_TEST(mmap_size_explicit_value);
    RUN_TEST(mmap_size_negative_clamped_to_zero);
    RUN_TEST(mmap_size_garbage_falls_back_to_default);
    RUN_TEST(mmap_size_partial_garbage_falls_back_to_default);
    RUN_TEST(store_open_with_mmap_disabled);
}
