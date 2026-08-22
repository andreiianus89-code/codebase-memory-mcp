/*
 * test_artifact.c — Tests for persistent artifact export/import.
 */
#include "test_framework.h"
#include "store/store.h"
#include "pipeline/artifact.h"
#include "pipeline/artifact_internal.h"
#include "pipeline/pipeline.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/compat_thread.h"
#include "foundation/constants.h"
#include "foundation/log.h"
#include "foundation/platform.h"
#include "foundation/sha256.h"

#include <sys/stat.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include "foundation/win_utf8.h"
#include <aclapi.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

/* ── Helpers ─────────────────────────────────────────────────────── */

static char g_tmpdir[1024];
static char g_repo[1024];
static char g_db[1024];
enum { ART_TEST_LOG_BUF = 32768 };
static char g_log_capture[ART_TEST_LOG_BUF];
static CBMLogLevel g_prev_log_level;

static void setup_artifact_test(void) {
    snprintf(g_tmpdir, sizeof(g_tmpdir), "%s/cbm_test_artifact_XXXXXX", cbm_tmpdir());
    cbm_mkdtemp(g_tmpdir);

    snprintf(g_repo, sizeof(g_repo), "%s/repo", g_tmpdir);
    cbm_mkdir_p(g_repo, 0755);

    snprintf(g_db, sizeof(g_db), "%s/test.db", g_tmpdir);
}

/* Create a minimal but valid DB with some nodes and edges. */
static void create_test_db(const char *path) {
    cbm_store_t *s = cbm_store_open_path(path);
    if (!s) {
        return;
    }

    cbm_store_exec(s, "INSERT OR IGNORE INTO projects(name, indexed_at, root_path) "
                      "VALUES('test-proj', '2026-01-01', '/tmp/test');");

    cbm_store_exec(s, "INSERT INTO nodes(project, label, name, qualified_name, file_path) "
                      "VALUES('test-proj', 'Function', 'foo', 'test-proj.foo', 'main.c');");
    cbm_store_exec(s, "INSERT INTO nodes(project, label, name, qualified_name, file_path) "
                      "VALUES('test-proj', 'Function', 'bar', 'test-proj.bar', 'main.c');");

    cbm_store_exec(s, "INSERT INTO edges(project, source_id, target_id, type) "
                      "VALUES('test-proj', 1, 2, 'CALLS');");

    cbm_store_close(s);
}

static void create_named_test_db(const char *path, const char *project, int node_count) {
    cbm_store_t *store = cbm_store_open_path(path);
    if (!store) {
        return;
    }
    cbm_store_upsert_project(store, project, "/tmp/artifact-concurrency");
    for (int i = 0; i < node_count; i++) {
        char name[64];
        char qualified[192];
        snprintf(name, sizeof(name), "node_%d", i);
        snprintf(qualified, sizeof(qualified), "%s.%s", project, name);
        cbm_node_t node = {.project = project,
                           .label = "Function",
                           .name = name,
                           .qualified_name = qualified,
                           .file_path = "artifact.c",
                           .start_line = i + 1,
                           .end_line = i + 1};
        (void)cbm_store_upsert_node(store, &node);
    }
    cbm_store_close(store);
}

static bool wait_for_atomic_int(const atomic_int *value, int expected, uint64_t timeout_ms) {
    uint64_t deadline = cbm_now_ms() + timeout_ms;
    while (atomic_load_explicit(value, memory_order_acquire) < expected &&
           cbm_now_ms() < deadline) {
        cbm_usleep(1000);
    }
    return atomic_load_explicit(value, memory_order_acquire) >= expected;
}

static bool wait_for_atomic_bool(const atomic_bool *value, uint64_t timeout_ms) {
    uint64_t deadline = cbm_now_ms() + timeout_ms;
    while (!atomic_load_explicit(value, memory_order_acquire) && cbm_now_ms() < deadline) {
        cbm_usleep(1000);
    }
    return atomic_load_explicit(value, memory_order_acquire);
}

#ifdef _WIN32
static bool artifact_windows_path_owner_private(const char *path) {
    wchar_t *wide = cbm_path_to_wide(path);
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    DWORD needed = 0;
    HANDLE directory =
        wide ? CreateFileW(wide, READ_CONTROL | FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
             : INVALID_HANDLE_VALUE;
    bool token_ready = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
                       !GetTokenInformation(token, TokenUser, NULL, 0, &needed) &&
                       GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
                       (user = malloc(needed)) != NULL &&
                       GetTokenInformation(token, TokenUser, user, needed, &needed) &&
                       user->User.Sid && IsValidSid(user->User.Sid);

    BY_HANDLE_FILE_INFORMATION information;
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    ACL_SIZE_INFORMATION acl_information;
    memset(&acl_information, 0, sizeof(acl_information));
    LPVOID opaque_ace = NULL;
    DWORD security_result =
        directory != INVALID_HANDLE_VALUE
            ? GetSecurityInfo(directory, SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL,
                              &dacl, NULL, &descriptor)
            : ERROR_INVALID_HANDLE;
    bool valid = token_ready && directory != INVALID_HANDLE_VALUE &&
                 GetFileType(directory) == FILE_TYPE_DISK &&
                 GetFileInformationByHandle(directory, &information) != 0 &&
                 (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                 (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                 security_result == ERROR_SUCCESS && descriptor && owner && dacl &&
                 EqualSid(owner, user->User.Sid) &&
                 GetSecurityDescriptorControl(descriptor, &control, &revision) &&
                 (control & SE_DACL_PRESENT) != 0 && (control & SE_DACL_PROTECTED) != 0 &&
                 GetAclInformation(dacl, &acl_information, sizeof(acl_information),
                                   AclSizeInformation) &&
                 acl_information.AceCount == 1 && GetAce(dacl, 0, &opaque_ace) && opaque_ace;
    if (valid) {
        ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)opaque_ace;
        PSID ace_sid = (PSID)&ace->SidStart;
        valid = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                ace->Header.AceSize >= sizeof(ACCESS_ALLOWED_ACE) &&
                (ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) == 0 &&
                IsValidSid(ace_sid) && EqualSid(ace_sid, user->User.Sid) &&
                (ace->Mask == FILE_ALL_ACCESS || ace->Mask == GENERIC_ALL);
    }
    if (descriptor) {
        (void)LocalFree(descriptor);
    }
    if (directory != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(directory);
    }
    free(user);
    if (token) {
        (void)CloseHandle(token);
    }
    free(wide);
    return valid;
}
#endif

typedef struct {
    const char *db_path;
    const char *repo_path;
    const char *project;
    atomic_bool started;
    atomic_bool done;
    int result;
} artifact_export_thread_t;

static void *artifact_export_thread(void *opaque) {
    artifact_export_thread_t *thread = opaque;
    atomic_store_explicit(&thread->started, true, memory_order_release);
    thread->result = cbm_artifact_export(thread->db_path, thread->repo_path, thread->project,
                                         CBM_ARTIFACT_FAST);
    atomic_store_explicit(&thread->done, true, memory_order_release);
    return NULL;
}

typedef struct {
    const char *repo_path;
    const char *cache_path;
    atomic_bool started;
    atomic_bool done;
    int result;
} artifact_import_thread_t;

static void *artifact_import_thread(void *opaque) {
    artifact_import_thread_t *thread = opaque;
    atomic_store_explicit(&thread->started, true, memory_order_release);
    thread->result = cbm_artifact_import(thread->repo_path, thread->cache_path);
    atomic_store_explicit(&thread->done, true, memory_order_release);
    return NULL;
}

static bool artifact_db_sidecars_absent(const char *path) {
    static const char *const suffixes[] = {"-wal", "-shm", "-journal"};
    char sidecar[1200];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(sidecar, sizeof(sidecar), "%s%s", path, suffixes[i]);
        if (n < 0 || (size_t)n >= sizeof(sidecar) || cbm_file_exists(sidecar)) {
            return false;
        }
    }
    return true;
}

static void cleanup_dir(const char *path) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static void write_text_file(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        return;
    }
    fputs(text, fp);
    fclose(fp);
}

static void capture_log_sink(const char *line) {
    size_t used = strlen(g_log_capture);
    size_t avail = sizeof(g_log_capture) - used;
    if (avail <= 1) {
        return;
    }
    int n = snprintf(g_log_capture + used, avail, "%s\n", line);
    if (n < 0 || (size_t)n >= avail) {
        g_log_capture[sizeof(g_log_capture) - 1] = '\0';
    }
}

static void capture_logs_start(void) {
    g_log_capture[0] = '\0';
    g_prev_log_level = cbm_log_get_level();
    cbm_log_set_level(CBM_LOG_DEBUG);
    cbm_log_set_sink(capture_log_sink);
}

static const char *capture_logs_end(void) {
    cbm_log_set_sink(NULL);
    cbm_log_set_level(g_prev_log_level);
    return g_log_capture;
}

/* ── Tests ───────────────────────────────────────────────────────── */

/* Rewrite the "original_size" number in an artifact.json in place, adding
 * `delta` to it. Returns false if the field / a digit run isn't found. */
static bool bump_artifact_original_size(const char *meta_path, long delta) {
    FILE *fp = fopen(meta_path, "rb");
    if (!fp) {
        return false;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    char *key = strstr(buf, "\"original_size\"");
    if (!key) {
        return false;
    }
    char *colon = strchr(key, ':');
    if (!colon) {
        return false;
    }
    char *ds = colon + 1;
    while (*ds == ' ' || *ds == '\t') {
        ds++;
    }
    char *de = ds;
    while (*de >= '0' && *de <= '9') {
        de++;
    }
    if (de == ds) {
        return false;
    }
    long val = strtol(ds, NULL, 10) + delta;
    char out[4096];
    int pre = (int)(ds - buf);
    snprintf(out, sizeof(out), "%.*s%ld%s", pre, buf, val, de);
    fp = fopen(meta_path, "wb");
    if (!fp) {
        return false;
    }
    fwrite(out, 1, strlen(out), fp);
    fclose(fp);
    return true;
}

static bool set_artifact_uint_field(const char *meta_path, const char *field,
                                    uint64_t value) {
    FILE *file = fopen(meta_path, "rb");
    if (!file) {
        return false;
    }
    char input[4096];
    size_t length = fread(input, 1, sizeof(input) - 1U, file);
    (void)fclose(file);
    input[length] = '\0';
    char key[128];
    int key_length = snprintf(key, sizeof(key), "\"%s\"", field ? field : "");
    char *entry = key_length > 0 && (size_t)key_length < sizeof(key) ? strstr(input, key) : NULL;
    char *colon = entry ? strchr(entry, ':') : NULL;
    char *digits = colon ? colon + 1 : NULL;
    while (digits && (*digits == ' ' || *digits == '\t')) {
        digits++;
    }
    char *end = digits;
    while (end && *end >= '0' && *end <= '9') {
        end++;
    }
    if (!digits || end == digits) {
        return false;
    }
    char replacement[32];
    int replacement_length = snprintf(replacement, sizeof(replacement), "%llu",
                                      (unsigned long long)value);
    size_t prefix = (size_t)(digits - input);
    size_t suffix = length - (size_t)(end - input);
    if (replacement_length <= 0 || (size_t)replacement_length >= sizeof(replacement) ||
        prefix + (size_t)replacement_length + suffix >= sizeof(input)) {
        return false;
    }
    char output[4096];
    memcpy(output, input, prefix);
    memcpy(output + prefix, replacement, (size_t)replacement_length);
    memcpy(output + prefix + (size_t)replacement_length, end, suffix);
    size_t output_length = prefix + (size_t)replacement_length + suffix;
    file = fopen(meta_path, "wb");
    bool written = file && fwrite(output, 1, output_length, file) == output_length;
    if (file) {
        written = fclose(file) == 0 && written;
    }
    return written;
}

static bool set_artifact_test_commit(const char *meta_path) {
    static const char commit[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    FILE *file = fopen(meta_path, "rb");
    if (!file) {
        return false;
    }
    char input[4096];
    size_t length = fread(input, 1, sizeof(input) - 1U, file);
    (void)fclose(file);
    input[length] = '\0';
    char *key = strstr(input, "\"commit\"");
    char *colon = key ? strchr(key, ':') : NULL;
    char *opening_quote = colon ? strchr(colon, '"') : NULL;
    char *closing_quote = opening_quote ? strchr(opening_quote + 1, '"') : NULL;
    if (!opening_quote || closing_quote != opening_quote + 1) {
        return false;
    }
    size_t prefix = (size_t)(opening_quote + 1 - input);
    size_t suffix = length - (size_t)(closing_quote - input);
    if (prefix + sizeof(commit) - 1U + suffix >= sizeof(input)) {
        return false;
    }
    char output[4096];
    memcpy(output, input, prefix);
    memcpy(output + prefix, commit, sizeof(commit) - 1U);
    memcpy(output + prefix + sizeof(commit) - 1U, closing_quote, suffix);
    size_t output_length = prefix + sizeof(commit) - 1U + suffix;
    file = fopen(meta_path, "wb");
    bool written = file && fwrite(output, 1, output_length, file) == output_length;
    if (file) {
        written = fclose(file) == 0 && written;
    }
    return written;
}

static bool mutate_artifact_payload_same_size(const char *payload_path) {
    struct stat before;
    if (stat(payload_path, &before) != 0 || before.st_size <= 1) {
        return false;
    }
    FILE *file = fopen(payload_path, "rb+");
    if (!file) {
        return false;
    }
    long offset = (long)(before.st_size / 2);
    bool changed = fseek(file, offset, SEEK_SET) == 0;
    int byte = changed ? fgetc(file) : EOF;
    changed = byte != EOF && fseek(file, offset, SEEK_SET) == 0 &&
              fputc(byte ^ 1, file) != EOF && fflush(file) == 0;
    changed = fclose(file) == 0 && changed;
    struct stat after;
    return changed && stat(payload_path, &after) == 0 && after.st_size == before.st_size;
}

TEST(artifact_same_size_mixed_bundle_fails_closed) {
    setup_artifact_test();
    create_test_db(g_db);
    ASSERT_EQ(cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST), 0);

    char metadata_path[1024];
    char payload_path[1024];
    char import_db[1024];
    snprintf(metadata_path, sizeof(metadata_path), "%s/.codebase-memory/artifact.json", g_repo);
    snprintf(payload_path, sizeof(payload_path), "%s/.codebase-memory/graph.db.zst", g_repo);
    snprintf(import_db, sizeof(import_db), "%s/mixed-import.db", g_tmpdir);

    /* Metadata limits are admission checks, before any payload-sized
     * allocation. Both an absurd frame claim and an impossible compression
     * bound must make all readers fail closed without creating the cache. */
    ASSERT_TRUE(set_artifact_uint_field(metadata_path, "original_size", UINT64_MAX));
    ASSERT_FALSE(cbm_artifact_exists(g_repo));
    ASSERT_NULL(cbm_artifact_commit(g_repo));
    ASSERT_NEQ(cbm_artifact_import(g_repo, import_db), 0);
    ASSERT_FALSE(cbm_file_exists(import_db));
    ASSERT_EQ(cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST), 0);

    ASSERT_TRUE(set_artifact_uint_field(metadata_path, "compressed_size", UINT64_MAX));
    ASSERT_FALSE(cbm_artifact_exists(g_repo));
    ASSERT_NULL(cbm_artifact_commit(g_repo));
    ASSERT_NEQ(cbm_artifact_import(g_repo, import_db), 0);
    ASSERT_FALSE(cbm_file_exists(import_db));
    ASSERT_EQ(cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST), 0);

    ASSERT_TRUE(set_artifact_test_commit(metadata_path));
    char *healthy_commit = cbm_artifact_commit(g_repo);
    ASSERT_NOT_NULL(healthy_commit);
    ASSERT_STR_EQ(healthy_commit, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    free(healthy_commit);

    /* Model a same-length generation-B payload paired with generation-A's
     * manifest. Length-only validation would accept it; the schema-v3 digest
     * binding must make every public reader fail closed. */
    ASSERT_TRUE(mutate_artifact_payload_same_size(payload_path));
    ASSERT_FALSE(cbm_artifact_exists(g_repo));
    ASSERT_NULL(cbm_artifact_commit(g_repo));
    ASSERT_NEQ(cbm_artifact_import(g_repo, import_db), 0);
    ASSERT_FALSE(cbm_file_exists(import_db));

    cleanup_dir(g_tmpdir);
    PASS();
}

/* The decompressed size is driven by the zstd frame's own content-size header,
 * not the separately-stored original_size field (which travels in plaintext
 * artifact.json and is trivially editable). A mismatch between the two must be
 * rejected — this is the check that keeps the destination allocation and the
 * decoder capacity pinned to the same verified size, so a doctored size can
 * never make the decoder write past the buffer. */
TEST(artifact_import_rejects_size_mismatch) {
    setup_artifact_test();
    create_test_db(g_db);
    ASSERT_EQ(cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST), 0);

    char meta[1024];
    snprintf(meta, sizeof(meta), "%s/.codebase-memory/artifact.json", g_repo);
    ASSERT_TRUE(
        bump_artifact_original_size(meta, 4096)); /* claim 4 KiB more than the frame holds */

    char import_db[1024];
    snprintf(import_db, sizeof(import_db), "%s/imported.db", g_tmpdir);
    int rc = cbm_artifact_import(g_repo, import_db);
    ASSERT_NEQ(rc, 0); /* must reject the mismatch, not import on the doctored size */

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_export_fast_roundtrip) {
    setup_artifact_test();
    create_test_db(g_db);

    /* Export with fast quality (zstd -3, no index stripping) */
    int rc = cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST);
    ASSERT_EQ(rc, 0);

    /* Verify artifact files exist */
    char zst[1024];
    snprintf(zst, sizeof(zst), "%s/.codebase-memory/graph.db.zst", g_repo);
    struct stat st;
    ASSERT_EQ(stat(zst, &st), 0);
    ASSERT_GT((int)st.st_size, 0);

    char meta[1024];
    snprintf(meta, sizeof(meta), "%s/.codebase-memory/artifact.json", g_repo);
    ASSERT_EQ(stat(meta, &st), 0);

    /* Import to a new path */
    char import_db[1024];
    snprintf(import_db, sizeof(import_db), "%s/imported.db", g_tmpdir);
    rc = cbm_artifact_import(g_repo, import_db);
    ASSERT_EQ(rc, 0);

    /* Verify imported DB has correct data */
    cbm_store_t *s = cbm_store_open_path(import_db);
    ASSERT_NOT_NULL(s);
    int nodes = cbm_store_count_nodes(s, "test-proj");
    int edges = cbm_store_count_edges(s, "test-proj");
    ASSERT_EQ(nodes, 2);
    ASSERT_EQ(edges, 1);
    cbm_store_close(s);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_export_best_roundtrip) {
    setup_artifact_test();
    create_test_db(g_db);

    cbm_store_t *src = cbm_store_open_path(g_db);
    ASSERT_NOT_NULL(src);
    ASSERT_EQ(cbm_store_prepare_for_publish(src), CBM_STORE_OK);
    cbm_store_close(src);
    ASSERT_TRUE(artifact_db_sidecars_absent(g_db));
    char digest_before[CBM_SHA256_HEX_LEN + 1];
    char digest_after[CBM_SHA256_HEX_LEN + 1];
    struct stat source_before;
    ASSERT_EQ(cbm_sha256_file(g_db, digest_before), 0);
    ASSERT_EQ(stat(g_db, &source_before), 0);

    /* Export with best quality (zstd -9, index stripping + VACUUM) */
    int rc = cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_BEST);
    ASSERT_EQ(rc, 0);

    /* Export is read-only with respect to the sealed source generation. */
    struct stat source_after;
    ASSERT_EQ(cbm_sha256_file(g_db, digest_after), 0);
    ASSERT_STR_EQ(digest_after, digest_before);
    ASSERT_EQ(stat(g_db, &source_after), 0);
    ASSERT_EQ(source_after.st_size, source_before.st_size);
    ASSERT_EQ(source_after.st_mtime, source_before.st_mtime);
    ASSERT_EQ(source_after.st_ctime, source_before.st_ctime);
#ifdef __APPLE__
    ASSERT_EQ(source_after.st_mtimespec.tv_nsec, source_before.st_mtimespec.tv_nsec);
    ASSERT_EQ(source_after.st_ctimespec.tv_nsec, source_before.st_ctimespec.tv_nsec);
#elif !defined(_WIN32)
    ASSERT_EQ(source_after.st_mtim.tv_nsec, source_before.st_mtim.tv_nsec);
    ASSERT_EQ(source_after.st_ctim.tv_nsec, source_before.st_ctim.tv_nsec);
#endif
    ASSERT_TRUE(artifact_db_sidecars_absent(g_db));
    src = cbm_store_open_path_query_strict(g_db);
    ASSERT_NOT_NULL(src);
    ASSERT_EQ(cbm_store_count_nodes(src, "test-proj"), 2);
    cbm_store_close(src);

    /* Import and verify */
    char import_db[1024];
    snprintf(import_db, sizeof(import_db), "%s/imported.db", g_tmpdir);
    rc = cbm_artifact_import(g_repo, import_db);
    ASSERT_EQ(rc, 0);

    cbm_store_t *s = cbm_store_open_path_query_strict(import_db);
    ASSERT_NOT_NULL(s);
    ASSERT_EQ(cbm_store_count_nodes(s, "test-proj"), 2);
    ASSERT_EQ(cbm_store_count_edges(s, "test-proj"), 1);
    cbm_store_close(s);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_exists_check) {
    setup_artifact_test();
    create_test_db(g_db);

    /* No artifact yet */
    ASSERT_FALSE(cbm_artifact_exists(g_repo));

    /* Export creates the artifact */
    cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST);
    ASSERT_TRUE(cbm_artifact_exists(g_repo));

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_commit_hash) {
    setup_artifact_test();
    create_test_db(g_db);

    cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST);

    /* commit hash may be empty if repo is not a git repo, but should not crash */
    char *commit = cbm_artifact_commit(g_repo);
    /* For a non-git directory, commit will be NULL (git rev-parse HEAD fails) */
    free(commit);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_schema_version_mismatch) {
    setup_artifact_test();
    create_test_db(g_db);
    cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST);

    /* Legacy schema-v2 metadata lacks the schema-v3 payload binding and must
     * fail closed even though its version is lower than the current one. */
    char meta[1024];
    snprintf(meta, sizeof(meta), "%s/.codebase-memory/artifact.json", g_repo);
    FILE *fp = fopen(meta, "w");
    ASSERT_NOT_NULL(fp);
    fprintf(fp, "{\"schema_version\": 2, \"original_size\": 1000}");
    fclose(fp);

    /* exists should return false for incompatible version */
    ASSERT_FALSE(cbm_artifact_exists(g_repo));
    ASSERT_NULL(cbm_artifact_commit(g_repo));

    /* Import should fail */
    char import_db[1024];
    snprintf(import_db, sizeof(import_db), "%s/imported.db", g_tmpdir);
    int rc = cbm_artifact_import(g_repo, import_db);
    ASSERT_NEQ(rc, 0);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_import_missing) {
    setup_artifact_test();

    /* Import from repo without artifact should fail gracefully */
    char import_db[1024];
    snprintf(import_db, sizeof(import_db), "%s/imported.db", g_tmpdir);
    int rc = cbm_artifact_import(g_repo, import_db);
    ASSERT_NEQ(rc, 0);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_gitattributes_created) {
    setup_artifact_test();
    create_test_db(g_db);

    cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST);

    char ga[1024];
    snprintf(ga, sizeof(ga), "%s/.codebase-memory/.gitattributes", g_repo);
    struct stat st;
    ASSERT_EQ(stat(ga, &st), 0);

    /* Attribute ORDER is load-bearing: gitattributes apply left to right and
     * the `binary` macro expands to `-diff -merge -text`, so a trailing
     * `binary` unsets a preceding `merge=ours` (git check-attr merge reports
     * "unset" and concurrent artifact refreshes produce binary conflicts
     * instead of auto-resolving). The driver must come after the macro. */
    FILE *gaf = fopen(ga, "r");
    ASSERT_NOT_NULL(gaf);
    char content[512] = {0};
    size_t rd = fread(content, 1, sizeof(content) - 1, gaf);
    (void)fclose(gaf);
    ASSERT_TRUE(rd > 0);
    ASSERT_NOT_NULL(strstr(content, CBM_ARTIFACT_FILENAME " binary merge=ours"));
    ASSERT_TRUE(strstr(content, "merge=ours binary") == NULL);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_export_rename_failure_logs_specific_error) {
    setup_artifact_test();
    create_test_db(g_db);

    char art_dir[1024];
    snprintf(art_dir, sizeof(art_dir), "%s/.codebase-memory", g_repo);
    cbm_mkdir_p(art_dir, 0755);

    char zst[1024];
    snprintf(zst, sizeof(zst), "%s/graph.db.zst", art_dir);
    cbm_mkdir_p(zst, 0755);

    capture_logs_start();
    int rc = cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST);
    const char *logs = capture_logs_end();

    ASSERT_NEQ(rc, 0);
    ASSERT_FALSE(cbm_artifact_exists(g_repo));
    ASSERT_NOT_NULL(cbm_artifact_export_last_error());
    ASSERT(strstr(cbm_artifact_export_last_error(), "write_artifact") != NULL);
    ASSERT(strstr(cbm_artifact_export_last_error(), "rename_temp") != NULL);
    ASSERT(strstr(logs, "msg=artifact.export") != NULL);
    ASSERT(strstr(logs, "stage=write_artifact") != NULL);
    ASSERT(strstr(logs, "err=rename_temp") != NULL);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(pipeline_persistence_export_failure_returns_error) {
    setup_artifact_test();

    char src[1024];
    snprintf(src, sizeof(src), "%s/main.c", g_repo);
    write_text_file(src, "int main(void) { return 0; }\n");

    char art_dir[1024];
    snprintf(art_dir, sizeof(art_dir), "%s/.codebase-memory", g_repo);
    cbm_mkdir_p(art_dir, 0755);

    char zst[1024];
    snprintf(zst, sizeof(zst), "%s/graph.db.zst", art_dir);
    cbm_mkdir_p(zst, 0755);

    cbm_pipeline_t *p = cbm_pipeline_new(g_repo, g_db, CBM_MODE_FAST);
    ASSERT_NOT_NULL(p);
    cbm_pipeline_set_persistence(p, true);

    capture_logs_start();
    int rc = cbm_pipeline_run(p);
    const char *logs = capture_logs_end();
    cbm_pipeline_free(p);

    ASSERT_NEQ(rc, 0);
    ASSERT_FALSE(cbm_artifact_exists(g_repo));
    ASSERT(strstr(logs, "msg=pipeline.err") != NULL);
    ASSERT(strstr(logs, "phase=artifact_export") != NULL);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_null_safety) {
    ASSERT_NEQ(cbm_artifact_export(NULL, "/tmp", "p", 0), 0);
    ASSERT_NEQ(cbm_artifact_export("/tmp/x.db", NULL, "p", 0), 0);
    ASSERT_NEQ(cbm_artifact_import(NULL, "/tmp/x.db"), 0);
    ASSERT_NEQ(cbm_artifact_import("/tmp", NULL), 0);
    ASSERT_FALSE(cbm_artifact_exists(NULL));
    ASSERT_NULL(cbm_artifact_commit(NULL));
    PASS();
}

/* ── git shell-out path safety ────────────────────────────────────────────────
 *
 * artifact.c shells out to git via cbm_popen with the repo path interpolated into
 * the command. It previously used single quotes (`git -C '%s'`) with NO validation
 * — but cmd.exe does not honor single quotes, so on Windows a repo path with a space
 * broke argument grouping, and an embedded quote/metacharacter could break out of the
 * intended argument entirely. The hardening validates the path and switches to double
 * quotes; cbm_artifact_repo_path_is_shell_safe() is the guard. Rejecting quotes and
 * shell/cmd.exe metacharacters is the contract; spaces must stay allowed (double
 * quotes handle them) — that is the concrete regression the single-quote form caused. */
TEST(artifact_repo_path_shell_safe_accepts_plain_and_spaced) {
    ASSERT_TRUE(cbm_artifact_repo_path_is_shell_safe("/home/user/repo"));
    ASSERT_TRUE(cbm_artifact_repo_path_is_shell_safe("C:/Users/me/repo"));
    ASSERT_TRUE(cbm_artifact_repo_path_is_shell_safe("/home/user/my repo")); /* space OK */
    PASS();
}

TEST(artifact_repo_path_shell_safe_rejects_injection) {
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe(NULL));
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("it's"));        /* single quote */
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("a\"b"));        /* double quote */
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("x; rm -rf /")); /* command sep */
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("$(whoami)"));   /* substitution */
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("a`id`b"));      /* backtick */
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("a|b"));         /* pipe */
    PASS();
}

TEST(artifact_repo_path_shell_safe_rejects_cmd_metachars_on_windows) {
#ifdef _WIN32
    /* cmd.exe expands %VAR%, delayed !VAR!, and escapes with ^ even inside double
     * quotes — git_context.c rejects these on Windows and this must match. */
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("C:/a%USERPROFILE%b"));
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("C:/a!b"));
    ASSERT_FALSE(cbm_artifact_repo_path_is_shell_safe("C:/a^b"));
#else
    /* POSIX shells treat % ! ^ literally inside double quotes — allowed. */
    ASSERT_TRUE(cbm_artifact_repo_path_is_shell_safe("/a%b"));
    ASSERT_TRUE(cbm_artifact_repo_path_is_shell_safe("/a^b"));
#endif
    PASS();
}

/* #895: the FAST export path (watcher/incremental auto-update) read the
 * raw main-file bytes of a live WAL-mode store — committed rows still in
 * the -wal were missing and mid-checkpoint reads produced torn snapshots
 * that imported as page-corrupted caches. Export must snapshot
 * consistently (VACUUM INTO) on BOTH quality levels. */
TEST(artifact_fast_export_snapshots_live_wal_store) {
    setup_artifact_test();
    enum { WAL_NODES = 60 };

    /* Live store: rows committed but NOT checkpointed into the main file —
     * exactly the state the watcher export runs against. */
    cbm_store_t *s = cbm_store_open_path(g_db);
    ASSERT_NOT_NULL(s);
    cbm_store_upsert_project(s, "test-proj", "/tmp/test");
    for (int i = 0; i < WAL_NODES; i++) {
        char name[64];
        char qn[128];
        snprintf(name, sizeof(name), "walnode_%03d", i);
        snprintf(qn, sizeof(qn), "test-proj.mod.%s", name);
        cbm_node_t n = {.project = "test-proj",
                        .label = "Function",
                        .name = name,
                        .qualified_name = qn,
                        .file_path = "mod.py",
                        .start_line = i + 1,
                        .end_line = i + 2};
        ASSERT_TRUE(cbm_store_upsert_node(s, &n) > 0);
    }

    /* Export WHILE the writer connection is still open. */
    ASSERT_EQ(cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST), 0);
    cbm_store_close(s);

    char import_db[1024];
    snprintf(import_db, sizeof(import_db), "%s/imported_wal.db", g_tmpdir);
    ASSERT_EQ(cbm_artifact_import(g_repo, import_db), 0);

    cbm_store_t *imp = cbm_store_open_path(import_db);
    ASSERT_NOT_NULL(imp);
    /* Torn snapshot = the WAL-resident rows are missing. */
    ASSERT_EQ(cbm_store_count_nodes(imp, "test-proj"), WAL_NODES);
    cbm_store_close(imp);
    PASS();
}

typedef struct {
    atomic_int reached;
    atomic_bool release;
    char paths[2][CBM_SZ_4K];
    char directories[2][CBM_SZ_4K];
    bool private_directory[2];
} artifact_snapshot_hook_t;

static void artifact_snapshot_path_hook(const char *snapshot_path, void *opaque) {
    artifact_snapshot_hook_t *hook = opaque;
    int slot = atomic_fetch_add_explicit(&hook->reached, 1, memory_order_acq_rel);
    if (slot >= 0 && slot < 2) {
        snprintf(hook->paths[slot], sizeof(hook->paths[slot]), "%s", snapshot_path);
        snprintf(hook->directories[slot], sizeof(hook->directories[slot]), "%s", snapshot_path);
        char *slash = strrchr(hook->directories[slot], '/');
        if (slash) {
            *slash = '\0';
#ifdef _WIN32
            hook->private_directory[slot] =
                artifact_windows_path_owner_private(hook->directories[slot]);
#else
            struct stat status;
            hook->private_directory[slot] = stat(hook->directories[slot], &status) == 0;
            hook->private_directory[slot] =
                hook->private_directory[slot] && (status.st_mode & 0777) == 0700;
#endif
        }
    }
    while (!atomic_load_explicit(&hook->release, memory_order_acquire)) {
        cbm_usleep(1000);
    }
}

TEST(artifact_concurrent_exports_use_unique_private_snapshots) {
    setup_artifact_test();
    create_named_test_db(g_db, "snapshot-a", 2);

    char repo_b[1024];
    char db_b[1024];
    snprintf(repo_b, sizeof(repo_b), "%s/repo-b", g_tmpdir);
    snprintf(db_b, sizeof(db_b), "%s/b.db", g_tmpdir);
    ASSERT_TRUE(cbm_mkdir_p(repo_b, 0755));
    create_named_test_db(db_b, "snapshot-b", 3);

    artifact_snapshot_hook_t hook = {0};
    atomic_init(&hook.reached, 0);
    atomic_init(&hook.release, false);
    cbm_artifact_set_snapshot_path_hook_for_test(artifact_snapshot_path_hook, &hook);

    artifact_export_thread_t first = {
        .db_path = g_db, .repo_path = g_repo, .project = "snapshot-a", .result = CBM_NOT_FOUND};
    artifact_export_thread_t second = {
        .db_path = db_b, .repo_path = repo_b, .project = "snapshot-b", .result = CBM_NOT_FOUND};
    atomic_init(&first.started, false);
    atomic_init(&first.done, false);
    atomic_init(&second.started, false);
    atomic_init(&second.done, false);
    cbm_thread_t first_thread;
    cbm_thread_t second_thread;
    int first_created = cbm_thread_create(&first_thread, 0, artifact_export_thread, &first);
    int second_created = cbm_thread_create(&second_thread, 0, artifact_export_thread, &second);
    bool both_reached = wait_for_atomic_int(&hook.reached, 2, 5000);
    atomic_store_explicit(&hook.release, true, memory_order_release);
    if (first_created == 0) {
        (void)cbm_thread_join(&first_thread);
    }
    if (second_created == 0) {
        (void)cbm_thread_join(&second_thread);
    }
    cbm_artifact_set_snapshot_path_hook_for_test(NULL, NULL);

    ASSERT_EQ(first_created, 0);
    ASSERT_EQ(second_created, 0);
    ASSERT_TRUE(both_reached);
    ASSERT_STR_NEQ(hook.paths[0], hook.paths[1]);
    ASSERT_STR_NEQ(hook.directories[0], hook.directories[1]);
    ASSERT_TRUE(hook.private_directory[0]);
    ASSERT_TRUE(hook.private_directory[1]);
    ASSERT_EQ(first.result, 0);
    ASSERT_EQ(second.result, 0);
    ASSERT_FALSE(cbm_file_exists(hook.directories[0]));
    ASSERT_FALSE(cbm_file_exists(hook.directories[1]));

    char cache_a[1024];
    char cache_b[1024];
    snprintf(cache_a, sizeof(cache_a), "%s/import-snapshot-a.db", g_tmpdir);
    snprintf(cache_b, sizeof(cache_b), "%s/import-snapshot-b.db", g_tmpdir);
    ASSERT_EQ(cbm_artifact_import(g_repo, cache_a), 0);
    ASSERT_EQ(cbm_artifact_import(repo_b, cache_b), 0);
    cbm_store_t *import_a = cbm_store_open_path_query_strict(cache_a);
    cbm_store_t *import_b = cbm_store_open_path_query_strict(cache_b);
    ASSERT_NOT_NULL(import_a);
    ASSERT_NOT_NULL(import_b);
    ASSERT_EQ(cbm_store_count_nodes(import_a, "snapshot-a"), 2);
    ASSERT_EQ(cbm_store_count_nodes(import_a, "snapshot-b"), 0);
    ASSERT_EQ(cbm_store_count_nodes(import_b, "snapshot-a"), 0);
    ASSERT_EQ(cbm_store_count_nodes(import_b, "snapshot-b"), 3);
    cbm_store_close(import_a);
    cbm_store_close(import_b);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_export_does_not_follow_fixed_temp_symlink) {
#ifdef _WIN32
    /* Windows symlink creation requires a developer-mode/elevated token; the
     * production path is covered by CREATE_NEW + OPEN_REPARSE_POINT. */
    PASS();
#else
    setup_artifact_test();
    create_test_db(g_db);
    char artifact_dir[1024];
    char sentinel[1024];
    char fixed_temp[1200];
    snprintf(artifact_dir, sizeof(artifact_dir), "%s/.codebase-memory", g_repo);
    snprintf(sentinel, sizeof(sentinel), "%s/outside-sentinel", g_tmpdir);
    snprintf(fixed_temp, sizeof(fixed_temp), "%s/graph.db.zst.tmp", artifact_dir);
    ASSERT_TRUE(cbm_mkdir_p(artifact_dir, 0755));
    write_text_file(sentinel, "outside-must-not-change\n");
    ASSERT_EQ(symlink(sentinel, fixed_temp), 0);

    ASSERT_EQ(cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST), 0);
    FILE *file = fopen(sentinel, "rb");
    ASSERT_NOT_NULL(file);
    char contents[64] = {0};
    size_t read_count = fread(contents, 1, sizeof(contents) - 1U, file);
    (void)fclose(file);
    struct stat link_status;
    ASSERT_TRUE(read_count > 0);
    ASSERT_STR_EQ(contents, "outside-must-not-change\n");
    ASSERT_EQ(lstat(fixed_temp, &link_status), 0);
    ASSERT_TRUE(S_ISLNK(link_status.st_mode));

    cleanup_dir(g_tmpdir);
    PASS();
#endif
}

typedef struct {
    atomic_bool hold_first;
    atomic_bool first_reached;
} artifact_bundle_hook_t;

static void artifact_bundle_payload_hook(const char *project_name, void *opaque) {
    artifact_bundle_hook_t *hook = opaque;
    if (strcmp(project_name, "generation-a") == 0) {
        atomic_store_explicit(&hook->first_reached, true, memory_order_release);
        while (atomic_load_explicit(&hook->hold_first, memory_order_acquire)) {
            cbm_usleep(1000);
        }
    }
}

static void artifact_bundle_snapshot_probe(const char *snapshot_path, void *opaque) {
    (void)snapshot_path;
    atomic_bool *reached = opaque;
    atomic_store_explicit(reached, true, memory_order_release);
}

TEST(artifact_repo_lock_keeps_two_file_bundle_consistent) {
    setup_artifact_test();
    char db_b[1024];
    char intermediate_cache[1024];
    char final_cache[1024];
    snprintf(db_b, sizeof(db_b), "%s/generation-b.db", g_tmpdir);
    snprintf(intermediate_cache, sizeof(intermediate_cache), "%s/intermediate.db", g_tmpdir);
    snprintf(final_cache, sizeof(final_cache), "%s/final.db", g_tmpdir);
    create_named_test_db(g_db, "generation-a", 2);
    create_named_test_db(db_b, "generation-b", 3);

    artifact_bundle_hook_t hook = {0};
    atomic_init(&hook.hold_first, true);
    atomic_init(&hook.first_reached, false);
    cbm_artifact_set_payload_published_hook_for_test(artifact_bundle_payload_hook, &hook);

    artifact_export_thread_t first = {.db_path = g_db,
                                      .repo_path = g_repo,
                                      .project = "generation-a",
                                      .result = CBM_NOT_FOUND};
    artifact_export_thread_t second = {.db_path = db_b,
                                       .repo_path = g_repo,
                                       .project = "generation-b",
                                       .result = CBM_NOT_FOUND};
    artifact_import_thread_t reader = {.repo_path = g_repo,
                                       .cache_path = intermediate_cache,
                                       .result = CBM_NOT_FOUND};
    artifact_import_thread_t second_reader = {.repo_path = g_repo,
                                              .cache_path = intermediate_cache,
                                              .result = CBM_NOT_FOUND};
    atomic_init(&first.started, false);
    atomic_init(&first.done, false);
    atomic_init(&second.started, false);
    atomic_init(&second.done, false);
    atomic_init(&reader.started, false);
    atomic_init(&reader.done, false);
    atomic_init(&second_reader.started, false);
    atomic_init(&second_reader.done, false);

    cbm_thread_t first_thread;
    cbm_thread_t second_thread;
    cbm_thread_t reader_thread;
    cbm_thread_t second_reader_thread;
    int first_created = cbm_thread_create(&first_thread, 0, artifact_export_thread, &first);
    bool first_paused = wait_for_atomic_bool(&hook.first_reached, 5000);

    /* POSIX coordinates on the pinned artifact-directory inode, not the
     * replaceable .gitattributes entry. Simulate Git/user replacement while A
     * owns the lock: B must still block on the same directory object. */
    bool attributes_replaced = true;
#ifndef _WIN32
    char attributes[1024];
    snprintf(attributes, sizeof(attributes), "%s/.codebase-memory/.gitattributes", g_repo);
    attributes_replaced = cbm_unlink(attributes) == 0;
    if (attributes_replaced) {
        write_text_file(attributes, "replacement while artifact lock is held\n");
        struct stat status;
        attributes_replaced = lstat(attributes, &status) == 0 && S_ISREG(status.st_mode);
    }
#endif

    atomic_bool second_passed_lock;
    atomic_init(&second_passed_lock, false);
    cbm_artifact_set_snapshot_path_hook_for_test(artifact_bundle_snapshot_probe,
                                                 &second_passed_lock);
    int second_created = cbm_thread_create(&second_thread, 0, artifact_export_thread, &second);
    int reader_created = cbm_thread_create(&reader_thread, 0, artifact_import_thread, &reader);
    int second_reader_created =
        cbm_thread_create(&second_reader_thread, 0, artifact_import_thread, &second_reader);
    bool second_started = wait_for_atomic_bool(&second.started, 5000);
    bool reader_started = wait_for_atomic_bool(&reader.started, 5000);
    bool second_reader_started = wait_for_atomic_bool(&second_reader.started, 5000);
    cbm_usleep(100000);
    bool writer_was_blocked =
        !atomic_load_explicit(&second_passed_lock, memory_order_acquire);
    bool readers_were_blocked = !atomic_load_explicit(&reader.done, memory_order_acquire) &&
                                !atomic_load_explicit(&second_reader.done, memory_order_acquire);

    atomic_store_explicit(&hook.hold_first, false, memory_order_release);
    if (first_created == 0) {
        (void)cbm_thread_join(&first_thread);
    }
    if (second_created == 0) {
        (void)cbm_thread_join(&second_thread);
    }
    if (reader_created == 0) {
        (void)cbm_thread_join(&reader_thread);
    }
    if (second_reader_created == 0) {
        (void)cbm_thread_join(&second_reader_thread);
    }
    cbm_artifact_set_payload_published_hook_for_test(NULL, NULL);
    cbm_artifact_set_snapshot_path_hook_for_test(NULL, NULL);

    ASSERT_EQ(first_created, 0);
    ASSERT_EQ(second_created, 0);
    ASSERT_EQ(reader_created, 0);
    ASSERT_EQ(second_reader_created, 0);
    ASSERT_TRUE(first_paused);
    ASSERT_TRUE(attributes_replaced);
    ASSERT_TRUE(second_started);
    ASSERT_TRUE(reader_started);
    ASSERT_TRUE(second_reader_started);
    ASSERT_TRUE(writer_was_blocked);
    ASSERT_TRUE(readers_were_blocked);
    ASSERT_EQ(first.result, 0);
    ASSERT_EQ(second.result, 0);
    ASSERT_TRUE((reader.result == 0) != (second_reader.result == 0));

    cbm_store_t *intermediate = cbm_store_open_path_query_strict(intermediate_cache);
    ASSERT_NOT_NULL(intermediate);
    int intermediate_a = cbm_store_count_nodes(intermediate, "generation-a");
    int intermediate_b = cbm_store_count_nodes(intermediate, "generation-b");
    cbm_store_close(intermediate);
    ASSERT_TRUE((intermediate_a == 2 && intermediate_b == 0) ||
                (intermediate_a == 0 && intermediate_b == 3));

    ASSERT_EQ(cbm_artifact_import(g_repo, final_cache), 0);
    cbm_store_t *final = cbm_store_open_path_query_strict(final_cache);
    ASSERT_NOT_NULL(final);
    ASSERT_EQ(cbm_store_count_nodes(final, "generation-a"), 0);
    ASSERT_EQ(cbm_store_count_nodes(final, "generation-b"), 3);
    cbm_store_close(final);

    cleanup_dir(g_tmpdir);
    PASS();
}

TEST(artifact_gitattributes_lock_contract_is_platform_specific) {
    setup_artifact_test();
    create_test_db(g_db);
    ASSERT_EQ(cbm_artifact_export(g_db, g_repo, "test-proj", CBM_ARTIFACT_FAST), 0);
    char attributes[1024];
    char metadata[1024];
    char import_db[1024];
    snprintf(attributes, sizeof(attributes), "%s/.codebase-memory/.gitattributes", g_repo);
    snprintf(metadata, sizeof(metadata), "%s/.codebase-memory/artifact.json", g_repo);
    snprintf(import_db, sizeof(import_db), "%s/legacy-import.db", g_tmpdir);
    ASSERT_TRUE(set_artifact_test_commit(metadata));
    ASSERT_EQ(cbm_unlink(attributes), 0);
#ifdef _WIN32
    ASSERT_FALSE(cbm_artifact_exists(g_repo));
    ASSERT_NULL(cbm_artifact_commit(g_repo));
    ASSERT_NEQ(cbm_artifact_import(g_repo, import_db), 0);
#else
    ASSERT_TRUE(cbm_artifact_exists(g_repo));
    char *commit = cbm_artifact_commit(g_repo);
    ASSERT_NOT_NULL(commit);
    ASSERT_STR_EQ(commit, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    free(commit);
    ASSERT_EQ(cbm_artifact_import(g_repo, import_db), 0);
    cbm_store_t *store = cbm_store_open_path_query_strict(import_db);
    ASSERT_NOT_NULL(store);
    ASSERT_EQ(cbm_store_count_nodes(store, "test-proj"), 2);
    cbm_store_close(store);
#endif

    cleanup_dir(g_tmpdir);
    PASS();
}

/* #895 (import half): page-level corruption must be refused at import.
 * The shallow integrity check only sanity-checks the projects table; the
 * deep variant runs PRAGMA quick_check and catches corrupt pages. */
TEST(store_deep_integrity_detects_page_corruption) {
    setup_artifact_test();
    enum { DEEP_NODES = 800, PAGE = 4096, ZERO_PAGES = 10 };
    char db2[1024];
    snprintf(db2, sizeof(db2), "%s/deep.db", g_tmpdir);
    cbm_store_t *s = cbm_store_open_path(db2);
    ASSERT_NOT_NULL(s);
    cbm_store_upsert_project(s, "deep", "/tmp/deep");
    for (int i = 0; i < DEEP_NODES; i++) {
        char name[64];
        char qn[192];
        snprintf(name, sizeof(name), "deep_probe_%04d", i);
        snprintf(qn, sizeof(qn), "deep.rather.long.module.path.for.page.fill.%s_pad_pad_pad",
                 name);
        cbm_node_t n = {.project = "deep",
                        .label = "Function",
                        .name = name,
                        .qualified_name = qn,
                        .file_path = "deep.py",
                        .start_line = i + 1,
                        .end_line = i + 2};
        ASSERT_TRUE(cbm_store_upsert_node(s, &n) > 0);
    }
    cbm_store_close(s);

    /* Healthy file passes the deep check. */
    cbm_store_t *ok = cbm_store_open_path(db2);
    ASSERT_NOT_NULL(ok);
    ASSERT_TRUE(cbm_store_check_integrity_deep(ok));
    cbm_store_close(ok);

    /* Zero a mid-file band and the deep check must refuse. */
    FILE *f = fopen(db2, "rb+");
    ASSERT_NOT_NULL(f);
    (void)fseek(f, 0, SEEK_END);
    long pages = ftell(f) / PAGE;
    ASSERT_TRUE(pages > ZERO_PAGES + 6);
    char zero[PAGE];
    memset(zero, 0, sizeof(zero));
    (void)fseek(f, (pages / 2) * (long)PAGE, SEEK_SET);
    for (int i = 0; i < ZERO_PAGES; i++) {
        ASSERT_EQ(fwrite(zero, 1, PAGE, f), (size_t)PAGE);
    }
    (void)fclose(f);

    cbm_store_t *bad = cbm_store_open_path(db2);
    ASSERT_NOT_NULL(bad);
    ASSERT_FALSE(cbm_store_check_integrity_deep(bad));
    cbm_store_close(bad);
    PASS();
}

SUITE(artifact) {
    RUN_TEST(artifact_same_size_mixed_bundle_fails_closed);
    RUN_TEST(artifact_concurrent_exports_use_unique_private_snapshots);
    RUN_TEST(artifact_export_does_not_follow_fixed_temp_symlink);
    RUN_TEST(artifact_repo_lock_keeps_two_file_bundle_consistent);
    RUN_TEST(artifact_gitattributes_lock_contract_is_platform_specific);
    RUN_TEST(artifact_fast_export_snapshots_live_wal_store);
    RUN_TEST(store_deep_integrity_detects_page_corruption);
    RUN_TEST(artifact_repo_path_shell_safe_accepts_plain_and_spaced);
    RUN_TEST(artifact_repo_path_shell_safe_rejects_injection);
    RUN_TEST(artifact_repo_path_shell_safe_rejects_cmd_metachars_on_windows);
    RUN_TEST(artifact_export_fast_roundtrip);
    RUN_TEST(artifact_export_best_roundtrip);
    RUN_TEST(artifact_exists_check);
    RUN_TEST(artifact_commit_hash);
    RUN_TEST(artifact_schema_version_mismatch);
    RUN_TEST(artifact_import_missing);
    RUN_TEST(artifact_gitattributes_created);
    RUN_TEST(artifact_export_rename_failure_logs_specific_error);
    RUN_TEST(pipeline_persistence_export_failure_returns_error);
    RUN_TEST(artifact_import_rejects_size_mismatch);
    RUN_TEST(artifact_null_safety);
}
