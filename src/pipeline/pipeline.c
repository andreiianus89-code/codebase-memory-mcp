/*
 * pipeline.c — Indexing pipeline orchestrator.
 *
 * Coordinates multi-pass indexing:
 *   1. Discover files
 *   2. Build structure (Project/Folder/Package/File nodes)
 *   3. Bulk load sources (read + LZ4 HC compress)
 *   4. Extract definitions (fused: extract + write nodes + build registry)
 *   5. Resolve imports, calls, usages, semantic edges
 *   6. Post-passes: tests, communities, HTTP links, git history
 *   7. Dump graph buffer to SQLite
 */
#include "foundation/constants.h"

enum { CBM_DIR_PERMS = 0755, PL_RING = 4, PL_RING_MASK = 3, PL_SEQ_PASSES = 6 };
#define PL_NSEC_PER_SEC 1000000000LL
#include "pipeline/pipeline.h"
#include "pipeline/artifact.h"
#include "pipeline/pipeline_internal.h"
#include "pipeline/pass_lsp_cross.h"
#include "pipeline/worker_pool.h"
#include "graph_buffer/graph_buffer.h"
#include "git/git_context.h"
#include "store/store.h"
#include "macro_table.h"
#include "lsp/scope.h"
#include "arena.h"
#include "discover/discover.h"
#include "discover/userconfig.h"
#include "foundation/platform.h"
#include "foundation/compat_fs.h"
#include "foundation/log.h"
#include "foundation/str_util.h"
#include "foundation/hash_table.h"
#include "foundation/compat.h"
#include "foundation/compat_thread.h"
#include "foundation/profile.h"
#include "foundation/mem.h"
#include "foundation/sha256.h"
#include "foundation/trusted_fs.h"
#include "foundation/limits.h"
#include "mcp/index_supervisor.h"
#include "semantic/semantic.h"
#ifdef _WIN32
#include "foundation/win_utf8.h"
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <sqlite3.h>
#include <yyjson/yyjson.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <time.h>

static inline void *intptr_to_ptr(intptr_t v) {
    void *p;
    memcpy(&p, &v, sizeof(p));
    return p;
}

/* ── Global index lock ─────────────────────────────────────────── */
/* Prevents concurrent pipeline runs on the same DB file.
 * Atomic spinlock: 0 = free, 1 = locked. */
static atomic_int g_pipeline_busy = 0;

bool cbm_pipeline_try_lock(void) {
    return atomic_exchange(&g_pipeline_busy, 1) == 0;
}

#define LOCK_SPIN_NS 100000000 /* 100ms between lock retries */

void cbm_pipeline_lock(void) {
    while (atomic_exchange(&g_pipeline_busy, 1) != 0) {
        struct timespec ts = {0, LOCK_SPIN_NS};
        cbm_nanosleep(&ts, NULL);
    }
}

void cbm_pipeline_unlock(void) {
    atomic_store(&g_pipeline_busy, 0);
}

static bool pipeline_recipe_fingerprint(char out[CBM_SHA256_HEX_LEN + 1]) {
    if (!out) {
        return false;
    }
    if (!cbm_index_supervisor_build_fingerprint() &&
        !cbm_index_supervisor_capture_build_fingerprint()) {
        return false;
    }
    const char *build = cbm_index_supervisor_build_fingerprint();
    char disabled_lsp[CBM_SZ_16];
    bool lsp_cross =
        cbm_safe_getenv("CBM_DISABLE_LSP_CROSS", disabled_lsp, sizeof(disabled_lsp), NULL) == NULL;
    cbm_sem_config_t semantic = cbm_sem_get_config();
    static const char *const graph_env_names[] = {
        "CBM_WALK_DEFS_MAX",      "CBM_TS_TYPE_BUDGET",      "CBM_LSP_DISABLED",
        "CBM_LSP_MAX_WALK_DEPTH", "CBM_INDEX_SINGLE_THREAD",
    };
    char env_hashes[sizeof(graph_env_names) / sizeof(graph_env_names[0])][CBM_SHA256_HEX_LEN + 1];
    for (size_t i = 0; i < sizeof(graph_env_names) / sizeof(graph_env_names[0]); i++) {
        const char *value = getenv(graph_env_names[i]);
        cbm_sha256_ctx env_hash;
        uint8_t digest[CBM_SHA256_DIGEST_LEN];
        cbm_sha256_init(&env_hash);
        const unsigned char present = value ? 1u : 0u;
        cbm_sha256_update(&env_hash, &present, sizeof(present));
        if (value) {
            cbm_sha256_update(&env_hash, value, strlen(value));
        }
        cbm_sha256_final(&env_hash, digest);
        static const char hex[] = "0123456789abcdef";
        for (size_t j = 0; j < sizeof(digest); j++) {
            env_hashes[i][j * 2] = hex[digest[j] >> 4];
            env_hashes[i][j * 2 + 1] = hex[digest[j] & 0x0f];
        }
        env_hashes[i][CBM_SHA256_HEX_LEN] = '\0';
    }
    int lsp_walk_depth = cbm_lsp_configure_max_walk_depth();
    char recipe[CBM_SZ_1K];
    int n = snprintf(recipe, sizeof(recipe),
                     "trusted-recipe-v2;build=%s;mode=full;tracked=1;"
                     "lsp_cross=%d;semantic=%d;semantic_threshold=%.9g;"
                     "max_file_bytes=%ld;auxiliary_manifest=v1;githistory=0;"
                     "walk_defs_env=%s;ts_type_budget_env=%s;lsp_disabled_env=%s;"
                     "lsp_walk_depth_env=%s;lsp_walk_depth=%d;single_thread_env=%s",
                     build ? build : "", lsp_cross ? 1 : 0, cbm_sem_is_enabled() ? 1 : 0,
                     (double)semantic.threshold, cbm_max_file_bytes(), env_hashes[0], env_hashes[1],
                     env_hashes[2], env_hashes[3], lsp_walk_depth, env_hashes[4]);
    if (!build || n < 0 || (size_t)n >= sizeof(recipe)) {
        return false;
    }
    cbm_sha256_hex(recipe, (size_t)n, out);
    return true;
}

/* ── Internal state ──────────────────────────────────────────────── */

struct cbm_pipeline {
    char *repo_path;
    char *db_path;
    char *project_name;
    cbm_git_context_t git_ctx;
    char *branch_qn;
    cbm_index_mode_t mode;
    bool git_tracked_only;
    char recipe_sha256[CBM_SHA256_HEX_LEN + 1];
    cbm_trusted_root_t *trusted_root;
    char *trusted_snapshot_dir;
    unsigned int trusted_snapshot_serial;
    bool trusted_validation_only;
#ifdef _WIN32
    HANDLE trusted_snapshot_dir_handle;
    BY_HANDLE_FILE_INFORMATION trusted_snapshot_dir_identity;
#else
    int trusted_snapshot_dir_fd;
    dev_t trusted_snapshot_dir_device;
    ino_t trusted_snapshot_dir_inode;
#endif
    char **tracked_paths;
    int tracked_path_count;
    cbm_file_info_t *auxiliary_files;
    cbm_file_snapshot_t *auxiliary_snapshots;
    int auxiliary_file_count;
    /* Source corpus retained until the atomic publication boundary so the
     * final hook-to-rename window is covered by the same digest contract. */
    cbm_file_info_t *publish_files;
    cbm_file_snapshot_t *publish_snapshots;
    int publish_file_count;
    atomic_int cancelled_storage;
    atomic_int *cancelled;
    bool persistence; /* write .codebase-memory/graph.db.zst after indexing */

    /* Indexing state (set during run) */
    cbm_gbuf_t *gbuf;
    cbm_registry_t *registry;

    /* Directory subtrees skipped during discovery (rel paths). Captured from
     * cbm_discover_ex so the MCP layer can report excluded subtrees (#411).
     * Owned by the pipeline; freed in cbm_pipeline_free. */
    char **excluded_dirs;
    int excluded_count;

    /* Individual files dropped by ignore rules during discovery (#963
     * "purposely not indexed" — by design, not failures). Stored entries are
     * capped in discovery; ignored_total keeps the uncapped count so
     * truncation stays explicit. Owned by the pipeline. */
    cbm_ignored_file_t *ignored_files;
    int ignored_count;
    int ignored_total;

    /* Per-file indexing failures (skipped files) surfaced via MCP/CLI/logfile
     * (Stage 2 / Track B). A skip is the expected handled outcome of a bad or
     * oversized file — the run still succeeds ("indexed"). Owned by the
     * pipeline; freed in cbm_pipeline_free. */
    cbm_file_error_t *file_errors;
    int file_errors_count;
    int file_errors_cap;
    bool error_recording_failed;
    atomic_int parser_read_failed;
    size_t parser_read_limit_for_tests;

    /* User-defined extension overrides (loaded once per run) */
    cbm_userconfig_t *userconfig;

    /* Committed graph size at dump time (-1 = dump did not run). #334 gate axis. */
    int committed_nodes;
    int committed_edges;

    /* ADR (project_summaries) captured before a full-reindex DB delete, so it
     * can be restored after the rebuild. NULL when no ADR existed. Issue #516. */
    char *saved_adr;

    /* Deterministic test-only seam at the final publication boundary. Kept
     * per pipeline so concurrent test/process activity cannot cross-trigger. */
    void (*before_publish_hook)(cbm_pipeline_t *, const char *, void *);
    void *before_publish_hook_ctx;
    void (*before_trusted_noop_hook)(cbm_pipeline_t *, const char *, void *);
    void *before_trusted_noop_hook_ctx;
    int (*rename_hook)(const char *, const char *, void *);
    void *rename_hook_ctx;
};

static bool pipeline_recipe_unchanged(const cbm_pipeline_t *p) {
    char current[CBM_SHA256_HEX_LEN + 1];
    return p && p->recipe_sha256[0] && pipeline_recipe_fingerprint(current) &&
           strcmp(current, p->recipe_sha256) == 0;
}

/* ── Global pkgmap (one active pipeline at a time) ─────────────── */

static CBMHashTable *g_pkgmap = NULL;

CBMHashTable *cbm_pipeline_get_pkgmap(void) {
    return g_pkgmap;
}

void cbm_pipeline_set_pkgmap(CBMHashTable *map) {
    g_pkgmap = map;
}

/* ── Timing helper ──────────────────────────────────────────────── */

static double elapsed_ms(struct timespec start) {
    struct timespec now;
    cbm_clock_gettime(CLOCK_MONOTONIC, &now);
    return ((double)(now.tv_sec - start.tv_sec) * CBM_MS_PER_SEC) +
           ((double)(now.tv_nsec - start.tv_nsec) / CBM_US_PER_SEC_F);
}

/* Format int to string for logging. Thread-safe via TLS rotating buffers. */
static const char *itoa_buf(int val) {
    static CBM_TLS char bufs[PL_RING][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & PL_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Log current + peak RSS at a pipeline phase boundary (memory profiling). */
static void log_phase_mem(const char *phase) {
    enum { PL_BYTES_PER_MB = 1024 * 1024 };
    cbm_log_info("mem.phase", "phase", phase, "rss_mb",
                 itoa_buf((int)(cbm_mem_rss() / PL_BYTES_PER_MB)), "peak_mb",
                 itoa_buf((int)(cbm_mem_peak_rss() / PL_BYTES_PER_MB)));
}

/* ── Lifecycle ──────────────────────────────────────────────────── */

cbm_pipeline_t *cbm_pipeline_new(const char *repo_path, const char *db_path,
                                 cbm_index_mode_t mode) {
    if (!repo_path) {
        return NULL;
    }

    cbm_pipeline_t *p = calloc(CBM_ALLOC_ONE, sizeof(cbm_pipeline_t));
    if (!p) {
        return NULL;
    }
#ifdef _WIN32
    p->trusted_snapshot_dir_handle = INVALID_HANDLE_VALUE;
#else
    p->trusted_snapshot_dir_fd = -1;
#endif

    char tracked_only_buf[CBM_SZ_16];
    const char *tracked_only =
        cbm_safe_getenv("CBM_GIT_TRACKED_ONLY", tracked_only_buf, sizeof(tracked_only_buf), "");
    p->git_tracked_only =
        tracked_only && (strcmp(tracked_only, "1") == 0 || strcmp(tracked_only, "true") == 0);
    p->repo_path = strdup(repo_path);
    p->db_path = db_path ? strdup(db_path) : NULL;
    p->project_name = cbm_project_name_from_path(repo_path);
    p->mode = mode;
    if (p->git_tracked_only) {
        /* Trusted snapshots have one semantic shape. Callers may still pass
         * FAST/MODERATE for compatibility, but the effective run is FULL. */
        p->mode = CBM_MODE_FULL;
        (void)pipeline_recipe_fingerprint(p->recipe_sha256);
        if (cbm_trusted_root_open(repo_path, &p->trusted_root) != 0) {
            cbm_pipeline_free(p);
            return NULL;
        }
        if (cbm_git_context_resolve_trusted(repo_path, p->trusted_root, &p->git_ctx) != 0) {
            cbm_pipeline_free(p);
            return NULL;
        }
    } else {
        (void)cbm_git_context_resolve(repo_path, &p->git_ctx);
    }
    p->branch_qn = cbm_git_context_branch_qn(p->project_name, &p->git_ctx);
    p->persistence = false;
    p->committed_nodes = -1;
    p->committed_edges = -1;
    atomic_init(&p->cancelled_storage, 0);
    atomic_init(&p->parser_read_failed, 0);
    p->cancelled = &p->cancelled_storage;

    return p;
}

void cbm_pipeline_set_persistence(cbm_pipeline_t *p, bool enabled) {
    if (p) {
        p->persistence = enabled;
    }
}

bool cbm_pipeline_set_project_name(cbm_pipeline_t *p, const char *name) {
    if (!p || !name || !name[0]) {
        return false;
    }

    char *normalized = cbm_project_name_from_path(name);
    if (!normalized) {
        return false;
    }
    if (!cbm_validate_project_name(normalized)) {
        free(normalized);
        return false;
    }

    free(p->project_name);
    p->project_name = normalized;
    free(p->branch_qn);
    p->branch_qn = cbm_git_context_branch_qn(p->project_name, &p->git_ctx);
    return true;
}

static void clear_publish_snapshot(cbm_pipeline_t *p) {
    if (!p) {
        return;
    }
    cbm_discover_free(p->publish_files, p->publish_file_count);
    p->publish_files = NULL;
    free(p->publish_snapshots);
    p->publish_snapshots = NULL;
    p->publish_file_count = 0;
}

void cbm_pipeline_free(cbm_pipeline_t *p) {
    if (!p) {
        return;
    }
    free(p->repo_path);
    free(p->db_path);
    free(p->project_name);
    cbm_git_free_tracked_files(p->tracked_paths, p->tracked_path_count);
    p->tracked_paths = NULL;
    p->tracked_path_count = 0;
    cbm_discover_free(p->auxiliary_files, p->auxiliary_file_count);
    p->auxiliary_files = NULL;
    free(p->auxiliary_snapshots);
    p->auxiliary_snapshots = NULL;
    p->auxiliary_file_count = 0;
    clear_publish_snapshot(p);
    cbm_discover_free_excluded(p->excluded_dirs, p->excluded_count);
    p->excluded_dirs = NULL;
    p->excluded_count = 0;
    cbm_discover_free_ignored(p->ignored_files, p->ignored_count);
    p->ignored_files = NULL;
    p->ignored_count = 0;
    p->ignored_total = 0;
    for (int i = 0; i < p->file_errors_count; i++) {
        free(p->file_errors[i].path);
        free(p->file_errors[i].reason);
        free(p->file_errors[i].phase);
    }
    free(p->file_errors);
    p->file_errors = NULL;
    p->file_errors_count = 0;
    p->file_errors_cap = 0;
    free(p->branch_qn);
    free(p->saved_adr); /* freed here too: error paths can exit before the
                         * restore in dump_and_persist_hashes runs. Issue #516. */
    p->saved_adr = NULL;
    cbm_git_context_free(&p->git_ctx);
    cbm_trusted_root_close(p->trusted_root);
    p->trusted_root = NULL;
    if (p->trusted_snapshot_dir) {
#ifdef _WIN32
        wchar_t *wide_dir = cbm_path_to_wide(p->trusted_snapshot_dir);
        DWORD dir_attributes = wide_dir ? GetFileAttributesW(wide_dir) : INVALID_FILE_ATTRIBUTES;
        if (dir_attributes != INVALID_FILE_ATTRIBUTES) {
            (void)SetFileAttributesW(wide_dir, dir_attributes & ~FILE_ATTRIBUTE_READONLY);
        }
        free(wide_dir);
#else
        (void)chmod(p->trusted_snapshot_dir, 0700);
#endif
        cbm_dir_t *dir = cbm_opendir(p->trusted_snapshot_dir);
        cbm_dirent_t *entry;
        while (dir && (entry = cbm_readdir(dir)) != NULL) {
            if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) {
                continue;
            }
            size_t dir_len = strlen(p->trusted_snapshot_dir);
            size_t name_len = strlen(entry->name);
            if (dir_len <= SIZE_MAX - name_len - PAIR_LEN) {
                char *path = (char *)malloc(dir_len + name_len + PAIR_LEN);
                if (path) {
                    snprintf(path, dir_len + name_len + PAIR_LEN, "%s/%s", p->trusted_snapshot_dir,
                             entry->name);
#ifdef _WIN32
                    wchar_t *wide_path = cbm_path_to_wide(path);
                    if (wide_path) {
                        (void)SetFileAttributesW(wide_path, FILE_ATTRIBUTE_NORMAL);
                        free(wide_path);
                    }
#else
                    (void)chmod(path, 0600);
#endif
                    (void)cbm_unlink(path);
                    free(path);
                }
            }
        }
        if (dir) {
            cbm_closedir(dir);
        }
#ifdef _WIN32
        if (p->trusted_snapshot_dir_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(p->trusted_snapshot_dir_handle);
            p->trusted_snapshot_dir_handle = INVALID_HANDLE_VALUE;
        }
#else
        if (p->trusted_snapshot_dir_fd >= 0) {
            close(p->trusted_snapshot_dir_fd);
            p->trusted_snapshot_dir_fd = -1;
        }
#endif
        (void)cbm_rmdir(p->trusted_snapshot_dir);
        free(p->trusted_snapshot_dir);
        p->trusted_snapshot_dir = NULL;
    }
    /* gbuf, store, registry freed during/after run */
    /* Defensively free userconfig in case run() was never called or panicked */
    if (p->userconfig) {
        cbm_set_user_lang_config(NULL);
        cbm_userconfig_free(p->userconfig);
        p->userconfig = NULL;
    }
    free(p);
}

void cbm_pipeline_cancel(cbm_pipeline_t *p) {
    if (p && p->cancelled) {
        atomic_store(p->cancelled, 1);
    }
}

void cbm_pipeline_bind_cancel_flag(cbm_pipeline_t *p, atomic_int *cancelled) {
    if (p && cancelled) {
        p->cancelled = cancelled;
    }
}

void cbm_pipeline_set_before_publish_hook_for_tests(
    cbm_pipeline_t *p, void (*hook)(cbm_pipeline_t *, const char *, void *), void *ctx) {
    if (p) {
        p->before_publish_hook = hook;
        p->before_publish_hook_ctx = ctx;
    }
}

void cbm_pipeline_set_before_trusted_noop_hook_for_tests(
    cbm_pipeline_t *p, void (*hook)(cbm_pipeline_t *, const char *, void *), void *ctx) {
    if (p) {
        p->before_trusted_noop_hook = hook;
        p->before_trusted_noop_hook_ctx = ctx;
    }
}

void cbm_pipeline_set_rename_hook_for_tests(cbm_pipeline_t *p,
                                            int (*hook)(const char *, const char *, void *),
                                            void *ctx) {
    if (p) {
        p->rename_hook = hook;
        p->rename_hook_ctx = ctx;
    }
}

const char *cbm_pipeline_project_name(const cbm_pipeline_t *p) {
    return p ? p->project_name : NULL;
}

const char *cbm_pipeline_repo_path(const cbm_pipeline_t *p) {
    return p ? p->repo_path : NULL;
}

bool cbm_pipeline_git_tracked_only(const cbm_pipeline_t *p) {
    return p && p->git_tracked_only;
}

bool cbm_pipeline_path_is_tracked(const cbm_pipeline_t *p, const char *rel_path) {
    if (!p || !rel_path || !p->tracked_paths || p->tracked_path_count <= 0) {
        return false;
    }
    int lo = 0;
    int hi = p->tracked_path_count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int cmp = strcmp(rel_path, p->tracked_paths[mid]);
        if (cmp == 0) {
            return true;
        }
        if (cmp < 0) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return false;
}

bool cbm_pipeline_path_is_auxiliary(const cbm_pipeline_t *p, const char *rel_path) {
    if (!p || !rel_path || !p->auxiliary_files || p->auxiliary_file_count <= 0) {
        return false;
    }
    int lo = 0;
    int hi = p->auxiliary_file_count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / PAIR_LEN;
        int cmp = strcmp(rel_path, p->auxiliary_files[mid].rel_path);
        if (cmp == 0) {
            return true;
        }
        if (cmp < 0) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return false;
}

void cbm_pipeline_get_auxiliary_files(const cbm_pipeline_t *p, const cbm_file_info_t **out_files,
                                      const cbm_file_snapshot_t **out_snapshots, int *out_count) {
    if (out_files) {
        *out_files = p ? p->auxiliary_files : NULL;
    }
    if (out_snapshots) {
        *out_snapshots = p ? p->auxiliary_snapshots : NULL;
    }
    if (out_count) {
        *out_count = p ? p->auxiliary_file_count : 0;
    }
}

atomic_int *cbm_pipeline_cancelled_ptr(cbm_pipeline_t *p) {
    return p ? p->cancelled : NULL;
}

int cbm_pipeline_get_mode(const cbm_pipeline_t *p) {
    return p ? (int)p->mode : 0;
}

void cbm_pipeline_get_excluded(const cbm_pipeline_t *p, char ***out, int *count) {
    if (out) {
        *out = p ? p->excluded_dirs : NULL;
    }
    if (count) {
        *count = p ? p->excluded_count : 0;
    }
}

/* NULL-safe heap strdup (avoids a strdup dependency + guards NULL inputs). */
static char *fe_strdup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d) {
        memcpy(d, s, n);
    }
    return d;
}

void cbm_pipeline_mark_error_recording_failed(cbm_pipeline_t *p) {
    if (p) {
        p->error_recording_failed = true;
    }
}

bool cbm_pipeline_fread_exact(cbm_pipeline_t *p, FILE *stream, void *buffer, size_t byte_count) {
    if (!stream || (!buffer && byte_count > 0)) {
        return false;
    }
    size_t requested = byte_count;
    if (p && p->parser_read_limit_for_tests > 0 && requested > p->parser_read_limit_for_tests) {
        requested = p->parser_read_limit_for_tests;
    }
    if (fread(buffer, 1, requested, stream) == byte_count) {
        return true;
    }
    if (p && p->git_tracked_only) {
        atomic_store_explicit(&p->parser_read_failed, 1, memory_order_relaxed);
    }
    return false;
}

void cbm_pipeline_set_parser_read_limit_for_tests(cbm_pipeline_t *p, size_t byte_count) {
    if (p) {
        p->parser_read_limit_for_tests = byte_count;
    }
}

bool cbm_pipeline_add_file_error(cbm_pipeline_t *p, const char *path, const char *reason,
                                 const char *phase) {
    if (!p) {
        return false;
    }
    char *path_copy = fe_strdup(path);
    char *reason_copy = fe_strdup(reason);
    char *phase_copy = fe_strdup(phase);
    if (!path_copy || !reason_copy || !phase_copy) {
        free(path_copy);
        free(reason_copy);
        free(phase_copy);
        cbm_pipeline_mark_error_recording_failed(p);
        return false;
    }
    if (p->file_errors_count >= p->file_errors_cap) {
        int ncap = p->file_errors_cap ? p->file_errors_cap * 2 : 16;
        cbm_file_error_t *grown =
            (cbm_file_error_t *)realloc(p->file_errors, (size_t)ncap * sizeof(*grown));
        if (!grown) {
            free(path_copy);
            free(reason_copy);
            free(phase_copy);
            cbm_pipeline_mark_error_recording_failed(p);
            return false;
        }
        p->file_errors = grown;
        p->file_errors_cap = ncap;
    }
    cbm_file_error_t *e = &p->file_errors[p->file_errors_count];
    e->path = path_copy;
    e->reason = reason_copy;
    e->phase = phase_copy;
    p->file_errors_count++;
    return true;
}

void cbm_pipeline_get_file_errors(const cbm_pipeline_t *p, cbm_file_error_t **out, int *count) {
    if (out) {
        *out = p ? p->file_errors : NULL;
    }
    if (count) {
        *count = p ? p->file_errors_count : 0;
    }
}

void cbm_pipeline_get_ignored(const cbm_pipeline_t *p, cbm_ignored_file_t **out, int *count,
                              int *total) {
    if (out) {
        *out = p ? p->ignored_files : NULL;
    }
    if (count) {
        *count = p ? p->ignored_count : 0;
    }
    if (total) {
        *total = p ? p->ignored_total : 0;
    }
}

void cbm_pipeline_get_committed_counts(const cbm_pipeline_t *p, int *nodes, int *edges) {
    if (nodes) {
        *nodes = p ? p->committed_nodes : -1;
    }
    if (edges) {
        *edges = p ? p->committed_edges : -1;
    }
}

void cbm_pipeline_set_committed_counts(cbm_pipeline_t *p, int nodes, int edges) {
    if (p) {
        p->committed_nodes = nodes;
        p->committed_edges = edges;
    }
}

static int refresh_git_context(cbm_pipeline_t *p) {
    cbm_git_context_t refreshed = {0};
    int resolve_rc =
        p->git_tracked_only
            ? cbm_git_context_resolve_trusted(p->repo_path, p->trusted_root, &refreshed)
            : cbm_git_context_resolve(p->repo_path, &refreshed);
    if (resolve_rc != 0) {
        return CBM_NOT_FOUND;
    }
    char *branch_qn = cbm_git_context_branch_qn(p->project_name, &refreshed);
    if (!branch_qn) {
        cbm_git_context_free(&refreshed);
        return CBM_NOT_FOUND;
    }
    cbm_git_context_free(&p->git_ctx);
    p->git_ctx = refreshed;
    free(p->branch_qn);
    p->branch_qn = branch_qn;
    return 0;
}

static bool nullable_string_equal(const char *lhs, const char *rhs) {
    return (!lhs && !rhs) || (lhs && rhs && strcmp(lhs, rhs) == 0);
}

int cbm_pipeline_verify_git_snapshot(const cbm_pipeline_t *p) {
    if (!p || !p->git_tracked_only || !p->git_ctx.is_git || !p->branch_qn) {
        return p && !p->git_tracked_only ? 0 : CBM_NOT_FOUND;
    }
    cbm_git_context_t current = {0};
    char *current_branch_qn = NULL;
    char **current_paths = NULL;
    int current_count = 0;
    bool matches = p->trusted_root &&
                   cbm_trusted_root_matches_path(p->trusted_root, p->repo_path) &&
                   cbm_git_context_resolve_trusted(p->repo_path, p->trusted_root, &current) == 0 &&
                   current.is_git;
    if (matches) {
        current_branch_qn = cbm_git_context_branch_qn(p->project_name, &current);
        matches = current_branch_qn && nullable_string_equal(current_branch_qn, p->branch_qn) &&
                  nullable_string_equal(current.branch, p->git_ctx.branch) &&
                  current.is_git == p->git_ctx.is_git &&
                  current.is_worktree == p->git_ctx.is_worktree &&
                  current.is_detached == p->git_ctx.is_detached &&
                  current.root_exists == p->git_ctx.root_exists &&
                  nullable_string_equal(current.head_sha, p->git_ctx.head_sha) &&
                  nullable_string_equal(current.base_sha, p->git_ctx.base_sha) &&
                  nullable_string_equal(current.worktree_root, p->git_ctx.worktree_root) &&
                  nullable_string_equal(current.git_common_dir, p->git_ctx.git_common_dir) &&
                  nullable_string_equal(current.canonical_root, p->git_ctx.canonical_root) &&
                  cbm_git_list_tracked_files_trusted(p->repo_path, p->trusted_root, &current_paths,
                                                     &current_count) == 0 &&
                  current_count == p->tracked_path_count;
    }
    for (int i = 0; matches && i < current_count; i++) {
        matches = strcmp(current_paths[i], p->tracked_paths[i]) == 0;
    }
    cbm_git_free_tracked_files(current_paths, current_count);
    free(current_branch_qn);
    cbm_git_context_free(&current);
    if (!matches) {
        cbm_log_error("pipeline.snapshot", "status", "git_state_changed_during_index");
        return CBM_NOT_FOUND;
    }
    return 0;
}

static bool project_active_branch_matches(const cbm_pipeline_t *p, cbm_store_t *store) {
    if (!p || !store || !p->branch_qn) {
        return false;
    }
    cbm_node_t project = {0};
    if (cbm_store_find_node_by_qn(store, p->project_name, p->project_name, &project) !=
        CBM_STORE_OK) {
        return false;
    }
    yyjson_doc *doc = project.properties_json
                          ? yyjson_read(project.properties_json, strlen(project.properties_json), 0)
                          : NULL;
    yyjson_val *root = doc ? yyjson_doc_get_root(doc) : NULL;
    yyjson_val *active =
        root && yyjson_is_obj(root) ? yyjson_obj_get(root, "active_branch_qn") : NULL;
    bool matches =
        active && yyjson_is_str(active) && strcmp(yyjson_get_str(active), p->branch_qn) == 0;
    if (matches && p->git_tracked_only) {
        yyjson_val *recipe = yyjson_obj_get(root, "index_recipe_sha256");
        matches = p->recipe_sha256[0] && recipe && yyjson_is_str(recipe) &&
                  strcmp(yyjson_get_str(recipe), p->recipe_sha256) == 0;
    }
    yyjson_doc_free(doc);
    cbm_node_free_fields(&project);
    return matches;
}

int cbm_pipeline_upsert_branch_metadata(cbm_pipeline_t *p, cbm_gbuf_t *gbuf) {
    if (!p || !gbuf || !p->branch_qn) {
        return CBM_NOT_FOUND;
    }
    const char *branch_name = p->git_ctx.branch ? p->git_ctx.branch : "working-tree";
    char *branch_props = cbm_git_context_props_json_alloc(&p->git_ctx);
    if (!branch_props || (p->git_tracked_only && !p->recipe_sha256[0])) {
        free(branch_props);
        return CBM_NOT_FOUND;
    }
    yyjson_mut_doc *project_doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *project_obj = project_doc ? yyjson_mut_obj(project_doc) : NULL;
    if (!project_doc || !project_obj) {
        yyjson_mut_doc_free(project_doc);
        free(branch_props);
        return CBM_NOT_FOUND;
    }
    yyjson_mut_doc_set_root(project_doc, project_obj);
    yyjson_mut_obj_add_strcpy(project_doc, project_obj, "active_branch_qn", p->branch_qn);
    if (p->git_tracked_only) {
        yyjson_mut_obj_add_strcpy(project_doc, project_obj, "index_recipe_sha256",
                                  p->recipe_sha256);
    }
    char *project_props = yyjson_mut_write(project_doc, 0, NULL);
    yyjson_mut_doc_free(project_doc);
    if (!project_props || cbm_gbuf_upsert_node(gbuf, "Project", p->project_name, p->project_name,
                                               NULL, 0, 0, project_props) <= 0) {
        free(project_props);
        free(branch_props);
        return CBM_NOT_FOUND;
    }
    free(project_props);
    bool branch_existed = cbm_gbuf_find_by_qn(gbuf, p->branch_qn) != NULL;
    int64_t branch_id =
        cbm_gbuf_upsert_node(gbuf, "Branch", branch_name, p->branch_qn, NULL, 0, 0, branch_props);
    if (branch_id <= 0) {
        free(branch_props);
        return CBM_NOT_FOUND;
    }
    if (!branch_existed) {
        const cbm_gbuf_node_t *project_node = cbm_gbuf_find_by_qn(gbuf, p->project_name);
        if (project_node && cbm_gbuf_insert_edge(gbuf, project_node->id, branch_id, "HAS_BRANCH",
                                                 branch_props) <= 0) {
            free(branch_props);
            return CBM_NOT_FOUND;
        }
    }
    free(branch_props);
    return 0;
}

bool cbm_pipeline_branch_metadata_changed(const cbm_pipeline_t *p, cbm_store_t *store) {
    if (!p || !store || !p->branch_qn) {
        return false;
    }
    char *branch_props = cbm_git_context_props_json_alloc(&p->git_ctx);
    if (!branch_props || !project_active_branch_matches(p, store)) {
        free(branch_props);
        return true;
    }
    const char *expected_name = p->git_ctx.branch ? p->git_ctx.branch : "working-tree";
    cbm_node_t stored = {0};
    if (cbm_store_find_node_by_qn(store, p->project_name, p->branch_qn, &stored) != CBM_STORE_OK) {
        free(branch_props);
        return true;
    }
    bool changed = !stored.label || strcmp(stored.label, "Branch") != 0 || !stored.name ||
                   strcmp(stored.name, expected_name) != 0 || !stored.properties_json ||
                   strcmp(stored.properties_json, branch_props) != 0;
    cbm_node_free_fields(&stored);
    free(branch_props);
    return changed;
}

static int add_tracked_discovery_exclusion(cbm_pipeline_t *p, const char *rel_path) {
    p->ignored_total++;
    if (!p->git_tracked_only && p->ignored_count >= CBM_DISCOVER_IGNORED_CAP) {
        return 0;
    }
    if (p->git_tracked_only) {
        if (!p->ignored_files || p->ignored_count >= p->tracked_path_count) {
            return CBM_NOT_FOUND;
        }
    } else {
        cbm_ignored_file_t *grown = (cbm_ignored_file_t *)realloc(
            p->ignored_files, (size_t)(p->ignored_count + 1) * sizeof(*grown));
        if (!grown) {
            return CBM_NOT_FOUND;
        }
        p->ignored_files = grown;
    }
    cbm_ignored_file_t *entry = &p->ignored_files[p->ignored_count];
    entry->rel_path = strdup(rel_path);
    entry->reason = strdup("not-indexable-by-discovery");
    if (!entry->rel_path || !entry->reason) {
        free(entry->rel_path);
        free(entry->reason);
        entry->rel_path = NULL;
        entry->reason = NULL;
        return CBM_NOT_FOUND;
    }
    p->ignored_count++;
    return 0;
}

static bool path_has_suffix(const char *path, const char *suffix) {
    if (!path || !suffix) {
        return false;
    }
    size_t path_len = strlen(path);
    size_t suffix_len = strlen(suffix);
    return path_len >= suffix_len && strcmp(path + path_len - suffix_len, suffix) == 0;
}

static char *trusted_nominal_path(const cbm_pipeline_t *p, const char *rel_path) {
    if (!p || !p->repo_path || !rel_path || !rel_path[0] || rel_path[0] == '/') {
        return NULL;
    }
    size_t root_len = strlen(p->repo_path);
    size_t rel_len = strlen(rel_path);
    if (root_len > SIZE_MAX - rel_len - PAIR_LEN) {
        return NULL;
    }
    char *path = (char *)malloc(root_len + rel_len + PAIR_LEN);
    if (!path) {
        return NULL;
    }
    snprintf(path, root_len + rel_len + PAIR_LEN, "%s/%s", p->repo_path, rel_path);
    return path;
}

static bool trusted_path_has_skipped_directory(const char *rel_path) {
    if (!rel_path) {
        return true;
    }
    const char *component = rel_path;
    for (const char *slash = strchr(component, '/'); slash; slash = strchr(component, '/')) {
        size_t len = (size_t)(slash - component);
        if (len == 0 || len >= CBM_DIRENT_NAME_MAX) {
            return true;
        }
        char name[CBM_DIRENT_NAME_MAX];
        memcpy(name, component, len);
        name[len] = '\0';
        if (cbm_should_skip_dir(name, CBM_MODE_FULL)) {
            return true;
        }
        component = slash + 1;
    }
    return false;
}

static int trusted_path_depth(const char *rel_path) {
    int depth = 0;
    for (const char *p = rel_path; p && *p; p++) {
        if (*p == '/') {
            depth++;
        }
    }
    return depth;
}

/* Tracked non-source files whose contents can affect graph resolution. These
 * are hash-bound inputs, not coverage exclusions. User/global configuration
 * and ignore files are deliberately absent: trust mode does not consume them. */
static bool is_graph_auxiliary_path(const char *rel_path) {
    if (!rel_path) {
        return false;
    }
    const char *slash = strrchr(rel_path, '/');
    const char *basename = slash ? slash + SKIP_ONE : rel_path;
    return strcmp(basename, "package.json") == 0 || strcmp(basename, "go.mod") == 0 ||
           strcmp(basename, "Cargo.toml") == 0 || strcmp(basename, "pyproject.toml") == 0 ||
           strcmp(basename, "composer.json") == 0 || strcmp(basename, "pubspec.yaml") == 0 ||
           strcmp(basename, "pom.xml") == 0 || strcmp(basename, "build.gradle") == 0 ||
           strcmp(basename, "build.gradle.kts") == 0 || strcmp(basename, "mix.exs") == 0 ||
           strcmp(basename, "tsconfig.json") == 0 || strcmp(basename, "jsconfig.json") == 0 ||
           path_has_suffix(basename, ".gemspec");
}

/* One canonical predicate defines the trusted auxiliary corpus. It must be
 * used both while capturing current inputs and while classifying stored hash
 * rows; otherwise a recognized-but-depth-excluded manifest becomes a
 * permanent false mismatch on every subsequent strict admission. */
static bool is_graph_auxiliary_path_eligible(const char *rel_path) {
    if (!is_graph_auxiliary_path(rel_path) || trusted_path_has_skipped_directory(rel_path)) {
        return false;
    }
    const char *basename = strrchr(rel_path, '/');
    basename = basename ? basename + 1 : rel_path;
    int depth = trusted_path_depth(rel_path);
    bool alias_config =
        strcmp(basename, "tsconfig.json") == 0 || strcmp(basename, "jsconfig.json") == 0;
    return alias_config ? depth <= 32 : depth < 64;
}

static int refresh_graph_auxiliary_files(cbm_pipeline_t *p) {
    cbm_discover_free(p->auxiliary_files, p->auxiliary_file_count);
    p->auxiliary_files = NULL;
    free(p->auxiliary_snapshots);
    p->auxiliary_snapshots = NULL;
    p->auxiliary_file_count = 0;
    if (!p->git_tracked_only || p->tracked_path_count == 0) {
        return 0;
    }

    cbm_file_info_t *aux = (cbm_file_info_t *)calloc((size_t)p->tracked_path_count, sizeof(*aux));
    if (!aux) {
        return CBM_NOT_FOUND;
    }
    int count = 0;
    for (int i = 0; i < p->tracked_path_count; i++) {
        const char *rel_path = p->tracked_paths[i];
        if (!is_graph_auxiliary_path_eligible(rel_path)) {
            continue;
        }
        aux[count].path = trusted_nominal_path(p, rel_path);
        aux[count].rel_path = strdup(rel_path);
        aux[count].language = CBM_LANG_COUNT;
        aux[count].size = 0;
        if (!aux[count].path || !aux[count].rel_path) {
            cbm_discover_free(aux, count + 1);
            return CBM_NOT_FOUND;
        }
        count++;
    }
    if (count == 0) {
        free(aux);
        return 0;
    }
    p->auxiliary_files = aux;
    p->auxiliary_file_count = count;
    if (cbm_pipeline_capture_file_snapshots(p, p->auxiliary_files, p->auxiliary_file_count,
                                            &p->auxiliary_snapshots) != 0) {
        cbm_discover_free(p->auxiliary_files, p->auxiliary_file_count);
        p->auxiliary_files = NULL;
        p->auxiliary_file_count = 0;
        return CBM_NOT_FOUND;
    }
    cbm_log_info("pipeline.git_auxiliary", "files", itoa_buf(p->auxiliary_file_count));
    return 0;
}

/* Trust mode derives its corpus directly from Git's NUL-framed manifest.
 * It never walks the untracked filesystem, so an untracked directory fanout
 * cannot affect memory, latency, or graph membership. */
static int discover_tracked_files(cbm_pipeline_t *p, cbm_file_info_t **out, int *file_count) {
    if (!p || !p->git_tracked_only || !out || !file_count) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    *file_count = 0;
    cbm_git_free_tracked_files(p->tracked_paths, p->tracked_path_count);
    p->tracked_paths = NULL;
    p->tracked_path_count = 0;
    if (!p->git_ctx.is_git || !cbm_trusted_root_matches_path(p->trusted_root, p->repo_path) ||
        cbm_git_list_tracked_files_trusted(p->repo_path, p->trusted_root, &p->tracked_paths,
                                           &p->tracked_path_count) != 0) {
        cbm_log_error("pipeline.err", "phase", "git_tracked_files", "reason",
                      p->git_ctx.is_git ? "enumeration_failed" : "not_a_git_repository");
        return CBM_NOT_FOUND;
    }
    if (refresh_graph_auxiliary_files(p) != 0) {
        cbm_log_error("pipeline.err", "phase", "git_auxiliary_snapshot");
        return CBM_NOT_FOUND;
    }

    cbm_discover_free_excluded(p->excluded_dirs, p->excluded_count);
    p->excluded_dirs = NULL;
    p->excluded_count = 0;
    cbm_discover_free_ignored(p->ignored_files, p->ignored_count);
    p->ignored_files = NULL;
    p->ignored_count = 0;
    p->ignored_total = 0;
    if (p->tracked_path_count > 0) {
        p->ignored_files =
            (cbm_ignored_file_t *)calloc((size_t)p->tracked_path_count, sizeof(*p->ignored_files));
        if (!p->ignored_files) {
            return CBM_NOT_FOUND;
        }
    }
    cbm_file_info_t *files =
        p->tracked_path_count > 0
            ? (cbm_file_info_t *)calloc((size_t)p->tracked_path_count, sizeof(*files))
            : NULL;
    if (p->tracked_path_count > 0 && !files) {
        return CBM_NOT_FOUND;
    }
    int kept = 0;
    for (int i = 0; i < p->tracked_path_count; i++) {
        const char *rel_path = p->tracked_paths[i];
        const char *basename = strrchr(rel_path, '/');
        basename = basename ? basename + 1 : rel_path;
        CBMLanguage language = cbm_language_for_filename(basename);
        bool indexable = language != CBM_LANG_COUNT &&
                         !trusted_path_has_skipped_directory(rel_path) &&
                         !cbm_has_ignored_suffix(basename, CBM_MODE_FULL) &&
                         !cbm_should_skip_filename(basename, CBM_MODE_FULL) &&
                         !cbm_matches_fast_pattern(basename, CBM_MODE_FULL);
        if (!indexable) {
            if (cbm_pipeline_path_is_auxiliary(p, rel_path)) {
                continue;
            }
            if (add_tracked_discovery_exclusion(p, rel_path) != 0) {
                cbm_discover_free(files, kept);
                return CBM_NOT_FOUND;
            }
            continue;
        }
        files[kept].path = trusted_nominal_path(p, rel_path);
        files[kept].rel_path = strdup(rel_path);
        files[kept].language = language;
        if (!files[kept].path || !files[kept].rel_path) {
            cbm_discover_free(files, kept + 1);
            return CBM_NOT_FOUND;
        }
        kept++;
    }
    *out = files;
    *file_count = kept;
    cbm_log_info("pipeline.git_tracked_only", "tracked", itoa_buf(p->tracked_path_count),
                 "source_candidates", itoa_buf(kept), "auxiliary",
                 itoa_buf(p->auxiliary_file_count));
    return 0;
}

/* Effective worker count. The crash supervisor re-runs its worker single-
 * threaded (CBM_INDEX_SINGLE_THREAD=1) so a per-file marker can pin the EXACT
 * crasher; a parallel re-run would race the marker. Honour that override
 * everywhere the worker count drives the parallel/sequential decision, so the
 * whole extraction phase collapses to the deterministic sequential path. */
static int effective_worker_count(bool initial) {
    const char *st = getenv("CBM_INDEX_SINGLE_THREAD");
    if (st && st[0] == '1') {
        return 1;
    }
    return cbm_default_worker_count(initial);
}

/* Resolve the DB path for this pipeline. Caller must free(). */
static char *resolve_db_path(const cbm_pipeline_t *p) {
    if (!p) {
        return NULL;
    }
    if (p->db_path) {
        return strdup(p->db_path);
    }

    const char *cache_dir = cbm_resolve_cache_dir();
    cache_dir = cache_dir ? cache_dir : cbm_tmpdir();
    if (!cache_dir || !p->project_name) {
        return NULL;
    }
    size_t cache_len = strlen(cache_dir);
    size_t project_len = strlen(p->project_name);
    if (project_len > SIZE_MAX - cache_len) {
        return NULL;
    }
    size_t stem_len = cache_len + project_len;
    if (stem_len > SIZE_MAX - sizeof("/.db")) {
        return NULL;
    }
    size_t path_size = stem_len + sizeof("/.db");
    char *path = malloc(path_size);
    if (!path) {
        return NULL;
    }
    int n = snprintf(path, path_size, "%s/%s.db", cache_dir, p->project_name);
    if (n < 0 || (size_t)n >= path_size) {
        free(path);
        return NULL;
    }
    return path;
}

static int check_cancel(const cbm_pipeline_t *p) {
    return atomic_load(p->cancelled) ? CBM_NOT_FOUND : 0;
}

/* ── Hash table cleanup callback ─────────────────────────────────── */

static void free_seen_dir_key(const char *key, void *val, void *ud) {
    (void)val;
    (void)ud;
    free((void *)key);
}

/* ── Pass 1: Structure ──────────────────────────────────────────── */

/* Create Project, Folder/Package, and File nodes in the graph buffer. */
/* Walk directory chain upward, creating Folder nodes and CONTAINS_FOLDER edges. */
static void create_folder_chain(cbm_pipeline_t *p, const char *dir, CBMHashTable *seen_dirs) {
    char *walk = strdup(dir);
    while (walk[0] != '\0' && !cbm_ht_get(seen_dirs, walk)) {
        cbm_ht_set(seen_dirs, strdup(walk), intptr_to_ptr(SKIP_ONE));
        char *folder_qn = cbm_pipeline_fqn_folder(p->project_name, walk);
        const char *dir_base = strrchr(walk, '/');
        dir_base = dir_base ? dir_base + SKIP_ONE : walk;
        cbm_gbuf_upsert_node(p->gbuf, "Folder", dir_base, folder_qn, walk, 0, 0, "{}");

        char *pdir = strdup(walk);
        char *ps = strrchr(pdir, '/');
        if (ps) {
            *ps = '\0';
        } else {
            free(pdir);
            pdir = strdup("");
        }
        const char *pqn;
        char *pqn_heap = NULL;
        if (pdir[0] == '\0') {
            pqn = p->branch_qn ? p->branch_qn : p->project_name;
        } else {
            pqn_heap = cbm_pipeline_fqn_folder(p->project_name, pdir);
            pqn = pqn_heap;
        }
        const cbm_gbuf_node_t *fn = cbm_gbuf_find_by_qn(p->gbuf, folder_qn);
        const cbm_gbuf_node_t *pn = cbm_gbuf_find_by_qn(p->gbuf, pqn);
        if (fn && pn) {
            cbm_gbuf_insert_edge(p->gbuf, pn->id, fn->id, "CONTAINS_FOLDER", "{}");
        }
        free(folder_qn);
        free(pqn_heap);
        char *up = strrchr(walk, '/');
        if (up) {
            *up = '\0';
        } else {
            walk[0] = '\0';
        }
        free(pdir);
    }
    free(walk);
}

static int pass_structure(cbm_pipeline_t *p, const cbm_file_info_t *files, int file_count) {
    cbm_log_info("pass.start", "pass", "structure", "files", itoa_buf(file_count));

    /* Project node */
    cbm_gbuf_upsert_node(p->gbuf, "Project", p->project_name, p->project_name, NULL, 0, 0, "{}");
    const char *branch_qn = p->branch_qn ? p->branch_qn : p->project_name;
    if (cbm_pipeline_upsert_branch_metadata(p, p->gbuf) != 0) {
        return CBM_NOT_FOUND;
    }

    /* Collect unique directories and create Folder/Package nodes */
    CBMHashTable *seen_dirs = cbm_ht_create(CBM_SZ_256);

    for (int i = 0; i < file_count; i++) {
        const char *rel = files[i].rel_path;
        if (!rel) {
            continue;
        }

        /* Create File node */
        char *file_qn = cbm_pipeline_fqn_compute(p->project_name, rel, "__file__");
        /* Extract basename */
        const char *slash = strrchr(rel, '/');
        const char *basename = slash ? slash + SKIP_ONE : rel;

        char props[CBM_SZ_256];
        const char *ext = strrchr(basename, '.');
        snprintf(props, sizeof(props), "{\"extension\":\"%s\"}", ext ? ext : "");

        const char *qualified_name = file_qn;
        const char *file_path = rel;
        cbm_gbuf_upsert_node(p->gbuf, "File", basename, qualified_name, file_path, 0, 0, props);

        /* CONTAINS_FILE edge: parent dir -> file */
        char *dir = strdup(rel);
        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            {
                *last_slash = '\0';
            }
        } else {
            free(dir);
            dir = strdup("");
        }

        const char *parent_qn;
        char *parent_qn_heap = NULL;
        if (dir[0] == '\0') {
            parent_qn = branch_qn;
        } else {
            parent_qn_heap = cbm_pipeline_fqn_folder(p->project_name, dir);
            parent_qn = parent_qn_heap;
        }

        /* Walk up directory chain, creating Folder nodes */
        create_folder_chain(p, dir, seen_dirs);

        /* Now create the CONTAINS_FILE edge */
        const cbm_gbuf_node_t *fnode = cbm_gbuf_find_by_qn(p->gbuf, file_qn);
        const cbm_gbuf_node_t *pnode = cbm_gbuf_find_by_qn(p->gbuf, parent_qn);
        if (fnode && pnode) {
            cbm_gbuf_insert_edge(p->gbuf, pnode->id, fnode->id, "CONTAINS_FILE", "{}");
        }

        free(file_qn);
        free(dir);
        free(parent_qn_heap);
    }

    /* Free seen_dirs keys */
    cbm_ht_foreach(seen_dirs, free_seen_dir_key, NULL);
    cbm_ht_free(seen_dirs);

    cbm_log_info("pass.done", "pass", "structure", "nodes", itoa_buf(cbm_gbuf_node_count(p->gbuf)),
                 "edges", itoa_buf(cbm_gbuf_edge_count(p->gbuf)));
    return 0;
}

/* ── Pass 2: Definitions ─────────────────────────────────────────── */

/* Implemented in pass_definitions.c via cbm_pipeline_pass_definitions() */

/* ── Githistory compute thread (for fused post-pass parallelism) ─── */

typedef struct {
    const char *repo_path;
    cbm_githistory_result_t *result;
} gh_compute_arg_t;

static void *gh_compute_thread_fn(void *arg) {
    gh_compute_arg_t *a = arg;
    cbm_pipeline_githistory_compute(a->repo_path, a->result);
    return NULL;
}

/* Extract Route nodes from URL strings found in config files (YAML, HCL, TOML).
 * These are infrastructure-defined endpoints (Cloud Scheduler, Terraform). */
/* Process infra bindings: topic→URL pairs from IaC configs.
 * Creates Route nodes for endpoints and HANDLES edges linking
 * topic Routes to endpoint Routes (bridging the gap). */
/* Process one infra binding: create Route node + INFRA_MAPS edge. */
static int process_one_infra_binding(cbm_gbuf_t *gbuf, const CBMInfraBinding *ib,
                                     const char *rel_path) {
    char url_route_qn[CBM_ROUTE_QN_SIZE];
    snprintf(url_route_qn, sizeof(url_route_qn), "__route__infra__%s", ib->target_url);
    int64_t url_route_id = cbm_gbuf_upsert_node(gbuf, "Route", ib->target_url, url_route_qn,
                                                rel_path, 0, 0, "{\"source\":\"infra\"}");
    char topic_route_qn[CBM_ROUTE_QN_SIZE];
    snprintf(topic_route_qn, sizeof(topic_route_qn), "__route__%s__%s",
             ib->broker ? ib->broker : "async", ib->source_name);
    const cbm_gbuf_node_t *topic_route = cbm_gbuf_find_by_qn(gbuf, topic_route_qn);
    int64_t topic_route_id;
    if (topic_route) {
        topic_route_id = topic_route->id;
    } else {
        /* The config file IS the declaration that the topic/queue/schedule exists;
         * upsert its Route node so the binding maps even when no code-side dispatch
         * call created the node first (e.g. a standalone scheduler/subscription
         * manifest). */
        topic_route_id = cbm_gbuf_upsert_node(gbuf, "Route", ib->source_name, topic_route_qn,
                                              rel_path, 0, 0, ib->broker ? ib->broker : "async");
        if (topic_route_id <= 0) {
            return 0;
        }
    }
    char props[CBM_SZ_512];
    snprintf(props, sizeof(props), "{\"broker\":\"%s\",\"topic\":\"%s\",\"endpoint\":\"%s\"}",
             ib->broker ? ib->broker : "async", ib->source_name, ib->target_url);
    cbm_gbuf_insert_edge(gbuf, topic_route_id, url_route_id, "INFRA_MAPS", props);
    return SKIP_ONE;
}

static void cbm_pipeline_process_infra_bindings(cbm_gbuf_t *gbuf, const cbm_file_info_t *files,
                                                CBMFileResult **result_cache, int file_count) {
    int bindings = 0;
    for (int i = 0; i < file_count; i++) {
        if (!result_cache[i]) {
            continue;
        }
        for (int bi = 0; bi < result_cache[i]->infra_bindings.count; bi++) {
            const CBMInfraBinding *ib = &result_cache[i]->infra_bindings.items[bi];
            if (ib->source_name && ib->target_url) {
                bindings += process_one_infra_binding(gbuf, ib, files[i].rel_path);
            }
        }
    }
    if (bindings > 0) {
        char buf[CBM_SZ_16];
        snprintf(buf, sizeof(buf), "%d", bindings);
        cbm_log_info("pass.infra_bindings", "linked", buf);
    }
}

static bool is_infra_file(const char *fp) {
    return fp != NULL &&
           (strstr(fp, ".yaml") != NULL || strstr(fp, ".yml") != NULL ||
            strstr(fp, ".tf") != NULL || strstr(fp, ".hcl") != NULL || strstr(fp, ".toml") != NULL);
}

/* CI/tooling configs describe the development TOOLCHAIN — their URLs are
 * repository/action/registry references, never endpoints this service
 * exposes. Minting infra Route nodes from them lets the route matcher's
 * root-service heuristic attach every handler of an ambiguous "/" route to
 * each tooling URL (junk HANDLES churn on plain pallets/flask, #999).
 * Deny by file identity, not URL shape: deployment configs (Cloud
 * Scheduler, compose) keep minting their genuine endpoints. */
static bool is_ci_tooling_config(const char *fp) {
    if (!fp) {
        return false;
    }
    if (strstr(fp, ".github/") != NULL || strstr(fp, ".gitlab/") != NULL ||
        strstr(fp, ".circleci/") != NULL) {
        return true;
    }
    const char *slash = strrchr(fp, '/');
    const char *base = slash ? slash + 1 : fp;
    static const char *const tooling[] = {".pre-commit-config.yaml",
                                          ".pre-commit-hooks.yaml",
                                          ".gitlab-ci.yml",
                                          ".travis.yml",
                                          "azure-pipelines.yml",
                                          "appveyor.yml",
                                          "bitbucket-pipelines.yml",
                                          ".readthedocs.yaml",
                                          ".readthedocs.yml",
                                          "codecov.yml",
                                          ".codecov.yml",
                                          ".goreleaser.yaml",
                                          ".goreleaser.yml",
                                          ".golangci.yml",
                                          ".golangci.yaml",
                                          NULL};
    for (int i = 0; tooling[i]; i++) {
        if (strcmp(base, tooling[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* True when a YAML key path denotes an UPSTREAM dependency, CONFIG value, or
 * HEALTHCHECK target rather than an endpoint this service exposes. Such URLs
 * (auth JWKS, downstream service base URLs, package-registry URLs, healthcheck
 * curl targets) are NOT routes the service serves and must not mint Route nodes
 * (#521). Exposed-endpoint keys (push_endpoint, post_url, callback, webhook)
 * are intentionally absent here so they still produce infra Route nodes. */
static bool is_upstream_config_key(const char *key_path) {
    if (!key_path) {
        /* No key context (e.g. flat string) — keep prior behaviour and mint. */
        return false;
    }
    static const char *const deny[] = {"jwks",     "registry",     "registries", "healthcheck",
                                       "upstream", "_service_url", "auth",       NULL};
    for (int i = 0; deny[i]; i++) {
        if (strstr(key_path, deny[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* Try to create an infra Route node from one string_ref. */
static void try_upsert_infra_route(cbm_gbuf_t *gbuf, const CBMStringRef *sr, const char *fp) {
    if (sr->kind != CBM_STRREF_URL || !sr->value || !strstr(sr->value, "://")) {
        return;
    }
    /* Skip upstream/config/healthcheck URLs — they are not exposed routes (#521). */
    if (is_upstream_config_key(sr->key_path)) {
        return;
    }
    char route_qn[CBM_ROUTE_QN_SIZE];
    snprintf(route_qn, sizeof(route_qn), "__route__infra__%s", sr->value);
    char route_props[CBM_SZ_512];
    if (sr->key_path) {
        snprintf(route_props, sizeof(route_props), "{\"source\":\"infra\",\"key_path\":\"%s\"}",
                 sr->key_path);
    } else {
        snprintf(route_props, sizeof(route_props), "{\"source\":\"infra\"}");
    }
    cbm_gbuf_upsert_node(gbuf, "Route", sr->value, route_qn, fp, 0, 0, route_props);
}

/* A URL string_ref that does NOT denote a route the service serves: a value
 * containing whitespace is a command/sentence with an embedded URL (e.g. a
 * Docker healthcheck `curl --fail http://... || exit 1`); a NULL key_path is a
 * context-less/duplicate ref; an upstream/config/healthcheck key is an external
 * dependency, not an exposed route. (#521) */
static bool route_sr_denied(const CBMStringRef *sr) {
    if (!sr->value || strchr(sr->value, ' ')) {
        return true;
    }
    if (!sr->key_path) {
        return true;
    }
    return is_upstream_config_key(sr->key_path);
}

static void cbm_pipeline_extract_infra_routes(cbm_gbuf_t *gbuf, const cbm_file_info_t *files,
                                              CBMFileResult **result_cache, int file_count) {
    /* DENY-WINS-BY-VALUE: the same URL is often extracted as several string_refs
     * at different key_path granularities (full path, leaf key, flat). The Route
     * node is keyed by VALUE, so it would be minted if ANY granularity passed the
     * per-ref guard — e.g. a denied full path `registries.terraform-registry.url`
     * is defeated by a sibling leaf `url`. So pass 1 collects every URL value
     * denied under ANY of its refs; pass 2 mints only values never denied. (#521) */
    CBMHashTable *denied = cbm_ht_create(16);
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < file_count; i++) {
            if (!result_cache[i] || !is_infra_file(files[i].rel_path) ||
                is_ci_tooling_config(files[i].rel_path)) {
                continue;
            }
            for (int si = 0; si < result_cache[i]->string_refs.count; si++) {
                const CBMStringRef *sr = &result_cache[i]->string_refs.items[si];
                if (sr->kind != CBM_STRREF_URL || !sr->value || !strstr(sr->value, "://")) {
                    continue;
                }
                if (pass == 0) {
                    if (denied && route_sr_denied(sr)) {
                        cbm_ht_set(denied, sr->value, (void *)1);
                    }
                } else if (!denied || !cbm_ht_has(denied, sr->value)) {
                    try_upsert_infra_route(gbuf, sr, files[i].rel_path);
                }
            }
        }
    }
    cbm_ht_free(denied);
}

/* Run decorator_tags, configlink, and route matching passes. */
typedef void (*predump_pass_fn)(cbm_pipeline_ctx_t *);
static void predump_deco(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_pass_decorator_tags(ctx->gbuf, ctx->project_name);
}
static void predump_route(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_create_route_nodes(ctx->gbuf);
}
static void predump_sim(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_pass_similarity(ctx);
}
static void predump_sem(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_pass_semantic_edges(ctx);
}
static void predump_cfg(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_pass_configlink(ctx);
}
static void predump_complexity(cbm_pipeline_ctx_t *ctx) {
    cbm_pipeline_pass_complexity(ctx);
}
static void run_predump_passes(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx) {
    static const struct {
        predump_pass_fn fn;
        const char *name;
        bool moderate_only; /* true = skip in fast mode */
    } passes[] = {
        {predump_deco, "decorator_tags", false}, {predump_cfg, "configlink", false},
        {predump_route, "route_match", false},   {predump_sim, "similarity", true},
        {predump_sem, "semantic_edges", true},   {predump_complexity, "complexity", false},
    };
    enum { PREDUMP_PASS_COUNT = 6 };
    struct timespec t;
    for (int i = 0; i < PREDUMP_PASS_COUNT && !check_cancel(p); i++) {
        /* "moderate_only" passes (similarity/semantic edges) run in FULL,
         * MODERATE and ADVANCED — they are skipped only in FAST. Compare
         * explicitly against FAST rather than `> MODERATE` so ADVANCED
         * (numerically 3) is not mistaken for a lighter mode than FULL. */
        if (passes[i].moderate_only && p->mode == CBM_MODE_FAST) {
            continue;
        }
        cbm_clock_gettime(CLOCK_MONOTONIC, &t);
        passes[i].fn(ctx);
        cbm_log_info("pass.timing", "pass", passes[i].name, "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t)));
    }
}

/* Adapter that lets cbm_pipeline_pass_lsp_cross slot into the seq_passes
 * dispatch table. The cross-file LSP needs the per-file CBMFileResult cache
 * to read defs/imports without re-extracting; in the sequential path that
 * cache is ctx->result_cache (set up by run_sequential_pipeline before
 * launching the dispatch loop). When the cache is unavailable (e.g. if the
 * pipeline opted out of caching), the pass becomes a no-op since there are
 * no extracted results to feed cross-file resolution. */
static int seq_pass_lsp_cross_dispatch(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                       int file_count) {
    if (!ctx || !ctx->result_cache)
        return 0;
    /* Cross-file LSP runs in every mode. */
    return cbm_pipeline_pass_lsp_cross(ctx, files, file_count, ctx->result_cache);
}

/* Run the sequential pipeline path: definitions, k8s, lsp_cross, calls, usages, semantic. */
/* Build the ObjectScript $$$macro table from .inc include files in the repo.
 * Returns NULL (and does no work) when no ObjectScript include files exist.
 * Caller owns the returned heap table (free via cbm_macro_table_free). */
CBMMacroTable *cbm_build_macro_table_from_files(const cbm_file_info_t *files, int count,
                                                const char *repo_path, cbm_pipeline_t *pipeline) {
    (void)repo_path;
    bool has_inc = false;
    for (int i = 0; i < count; i++) {
        if (files[i].language == CBM_LANG_OBJECTSCRIPT_ROUTINE && files[i].rel_path &&
            (strrchr(files[i].rel_path, '.') != NULL &&
             strcmp(strrchr(files[i].rel_path, '.'), ".inc") == 0)) {
            has_inc = true;
            break;
        }
    }
    if (!has_inc) {
        return NULL;
    }

    CBMMacroTable *mt = (CBMMacroTable *)calloc(1, sizeof(CBMMacroTable));
    if (!mt) {
        return NULL;
    }

    cbm_arena_init(&mt->arena);
    cbm_macro_table_init_system(mt);

    for (int i = 0; i < count; i++) {
        if (files[i].language != CBM_LANG_OBJECTSCRIPT_ROUTINE) {
            continue;
        }
        if (!files[i].path || !files[i].rel_path ||
            !(strrchr(files[i].rel_path, '.') != NULL &&
              strcmp(strrchr(files[i].rel_path, '.'), ".inc") == 0)) {
            continue;
        }
        FILE *f = cbm_fopen(files[i].path, "rb");
        if (!f) {
            continue;
        }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        rewind(f);
        if (fsize > 0) {
            char *src = (char *)malloc((size_t)fsize + 1);
            if (src) {
                if (cbm_pipeline_fread_exact(pipeline, f, src, (size_t)fsize)) {
                    src[fsize] = '\0';
                    cbm_parse_inc_file(mt, &mt->arena, src);
                }
                free(src);
            }
        }
        (void)fclose(f);
    }
    return mt;
}

static int run_sequential_pipeline(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                   const cbm_file_info_t *files, int file_count,
                                   struct timespec *t) {
    cbm_log_info("pipeline.mode", "mode", "sequential", "files", itoa_buf(file_count));

    /* Build package map from manifest files (sequential: read manifests directly).
     * Use the repo-walking variant so manifests filtered out by the main
     * discoverer (package.json, composer.json) still feed pkgmap and let
     * workspace imports like `@my/pkg` resolve to their target Module. */
    cbm_pipeline_set_pkgmap(
        cbm_pkgmap_build_from_repo_trusted(ctx->repo_path, files, file_count, ctx->project_name,
                                           ctx->excluded_dirs, ctx->excluded_count, ctx->pipeline));

    CBMFileResult **seq_cache = (CBMFileResult **)calloc(file_count, sizeof(CBMFileResult *));
    if (seq_cache) {
        ctx->result_cache = seq_cache;
    }

    /* ObjectScript: build the $$$macro table from .inc include files so that
     * pass_calls can resolve macro-mediated dispatch. NULL when not present. */
    CBMMacroTable *mt =
        cbm_build_macro_table_from_files(files, file_count, ctx->repo_path, ctx->pipeline);
    if (mt) {
        ctx->macro_table = mt;
    }
    typedef int (*seq_pass_fn)(cbm_pipeline_ctx_t *, const cbm_file_info_t *, int);
    static const struct {
        seq_pass_fn fn;
        const char *name;
        bool ignore_err;
    } seq_passes[] = {
        {cbm_pipeline_pass_definitions, "definitions", false},
        {cbm_pipeline_pass_k8s, "k8s", true},
        {seq_pass_lsp_cross_dispatch, "lsp_cross", true},
        {cbm_pipeline_pass_calls, "calls", false},
        {cbm_pipeline_pass_usages, "usages", false},
        {cbm_pipeline_pass_semantic, "semantic", false},
    };
    int rc = 0;
    for (int si = 0; si < PL_SEQ_PASSES && rc == 0; si++) {
        cbm_clock_gettime(CLOCK_MONOTONIC, t);
        int pr = seq_passes[si].fn(ctx, files, file_count);
        if (pr != 0 && !seq_passes[si].ignore_err) {
            rc = pr;
        }
        cbm_log_info("pass.timing", "pass", seq_passes[si].name, "elapsed_ms",
                     itoa_buf((int)elapsed_ms(*t)));
        if (check_cancel(p)) {
            rc = CBM_NOT_FOUND;
        }
    }
    /* Consume infra bindings (YAML/HCL topic/queue/scheduler → endpoint) so
     * INFRA_MAPS edges also form on the sequential path, not just the parallel
     * one. process_one_infra_binding self-creates the topic Route node when no
     * code-side dispatch created it (e.g. a standalone scheduler manifest). */
    if (seq_cache && rc == 0) {
        cbm_pipeline_extract_infra_routes(p->gbuf, files, seq_cache, file_count);
        cbm_pipeline_process_infra_bindings(p->gbuf, files, seq_cache, file_count);
    }
    if (seq_cache) {
        for (int i = 0; i < file_count; i++) {
            if (seq_cache[i]) {
                cbm_free_result(seq_cache[i]);
            }
        }
        free(seq_cache);
        ctx->result_cache = NULL;
    }
    /* Release the lsp_cross pass's shared registries only now: resolved_calls
     * borrowed registry-owned strings that the calls pass read above. */
    if (ctx->seq_cross_arena_live) {
        cbm_arena_destroy(&ctx->seq_cross_arena);
        ctx->seq_cross_arena_live = false;
    }
    /* Destroy this thread's TLS parser: the sequential path parses on the
     * CALLING thread (usually main), and a parser left alive here was
     * allocated in the current tree-sitter allocator epoch. A later
     * parallel run switches the global ts allocator to the slab
     * (cbm_slab_install); destroying the stale parser then frees
     * mimalloc-epoch memory through slab_free -> plain free() and libmalloc
     * aborts — the #773 second-index SIGABRT. */
    cbm_destroy_thread_parser();
    /* ObjectScript: free the macro / return-type tables built for this run. */
    if (ctx->macro_table) {
        cbm_macro_table_free((CBMMacroTable *)ctx->macro_table);
        ctx->macro_table = NULL;
    }
    if (ctx->return_type_table) {
        for (int i = 0; i < ctx->return_type_table->count; i++) {
            free((void *)ctx->return_type_table->entries[i].return_type);
        }
        free((void *)ctx->return_type_table);
        ctx->return_type_table = NULL;
    }
    return rc;
}

/* Run the parallel pipeline path: extract, registry, resolve, infra, k8s. */
static int run_parallel_pipeline(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                 const cbm_file_info_t *files, int file_count, int worker_count,
                                 struct timespec *t) {
    cbm_log_info("pipeline.mode", "mode", "parallel", "workers", itoa_buf(worker_count), "files",
                 itoa_buf(file_count));
    _Atomic int64_t shared_ids;
    atomic_init(&shared_ids, cbm_gbuf_next_id(p->gbuf));
    CBMFileResult **cache = (CBMFileResult **)calloc(file_count, sizeof(CBMFileResult *));
    if (!cache) {
        cbm_log_error("pipeline.err", "phase", "cache_alloc");
        return CBM_NOT_FOUND;
    }
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    int rc = cbm_parallel_extract(ctx, files, file_count, cache, &shared_ids, worker_count);
    cbm_log_info("pass.timing", "pass", "parallel_extract", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    if (rc != 0 || check_cancel(p)) {
        free(cache);
        return rc != 0 ? rc : CBM_NOT_FOUND;
    }
    cbm_gbuf_set_next_id(p->gbuf, atomic_load(&shared_ids));
    /* extract -> registry handoff: return the extract phase's freed-but-retained
     * allocator pages to the OS before registry_build allocates. On a 2x Linux
     * index the extract peak holds ~13 GB of reclaimable pages (peak_mb 20.7 vs
     * live rss_mb 7); not returning them pushed the process over the system
     * memory-pressure threshold and got it SIGKILLed at registry entry. */
    cbm_mem_collect();
    cbm_log_info("mem.collect", "phase", "post_extract", "rss_mb",
                 itoa_buf((int)(cbm_mem_rss() / (1024 * 1024))));
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    rc = cbm_build_registry_from_cache(ctx, files, file_count, cache);
    cbm_log_info("pass.timing", "pass", "registry_build", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    log_phase_mem("registry_build");
    if (rc != 0 || check_cancel(p)) {
        for (int i = 0; i < file_count; i++) {
            if (cache[i]) {
                cbm_free_result(cache[i]);
            }
        }
        free(cache);
        return rc != 0 ? rc : CBM_NOT_FOUND;
    }
    /* Cross-file LSP precondition: build a project-wide CBMLSPDef[]
     * once. The fused resolve_worker invokes cbm_pxc_run_one(_ts) per
     * file using these defs + the file's IMPORTS map, so cross-file
     * type-resolved CALLS land in result->resolved_calls before the
     * CALLS-edge emission. This replaces the old sequential
     * cbm_pipeline_pass_lsp_cross pass which re-read every source from
     * disk and re-parsed every tree on a single thread (~520s on
     * kubernetes). Soft-failure: NULL all_defs / NULL def_modules just
     * mean cross-file LSP no-ops; per-file LSP already ran during
     * extract. */
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    /* Cross-file LSP (type-aware call/usage resolution across files) — the
     * most expensive phase. CBM_DISABLE_LSP_CROSS=1 opts out (it can SIGSEGV
     * on large TS projects — see #340/#344); with cross-LSP off, all_defs
     * stays NULL and the fused resolver simply no-ops cross-file resolution
     * (per-file LSP already ran during extract). */
    char cbm_lsp_cross_env[CBM_SZ_16];
    const bool run_cross_lsp = cbm_safe_getenv("CBM_DISABLE_LSP_CROSS", cbm_lsp_cross_env,
                                               sizeof(cbm_lsp_cross_env), NULL) == NULL;
    if (!run_cross_lsp) {
        cbm_log_info("lsp_cross.skipped", "reason", "CBM_DISABLE_LSP_CROSS env set");
    }
    char **def_modules = NULL;
    int def_count = 0;
    CBMLSPDef *all_defs = NULL;
    if (run_cross_lsp) {
        def_modules = (char **)calloc((size_t)file_count, sizeof(char *));
        all_defs = def_modules
                       ? cbm_pxc_collect_all_defs(cache, files, file_count, ctx->project_name,
                                                  def_modules, &def_count)
                       : NULL;
    }
    /* Build inverted index: module_qn → defs. The fused resolve_worker
     * uses this to filter the global all_defs[] down to just the defs
     * each file actually needs (own_module + imported modules) — the
     * gopls "package summary" pattern. Drops per-file registry build
     * cost from O(all_defs) to O(relevant_defs), typically 50-100×
     * smaller per file. */
    CBMModuleDefIndex *module_def_index =
        all_defs ? cbm_pxc_build_module_def_index(all_defs, def_count) : NULL;
    /* Tier 2 full: pre-build per-language cross-LSP registries.
     * Built ONCE here; shared READ-ONLY across all files of that language
     * during resolve. Per-file work is then: parse + AST walk + O(1) lookups
     * — no registry build, no Phase 1b mutations. Languages added so far:
     * Go, Python. Others (C/C++, TS/JS, PHP, C#) fall back to per-file. */
    CBMArena cross_lsp_arena;
    cbm_arena_init(&cross_lsp_arena);
    CBMCrossLspRegistries cross_registries = {0};
    if (all_defs) {
        cross_registries.go = cbm_go_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.python =
            cbm_py_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.c = cbm_c_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.cs = cbm_cs_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        cross_registries.ts = cbm_ts_build_cross_registry(&cross_lsp_arena, all_defs, def_count);
        /* Rust: NOT built here. The shared all_defs registry is built LAZILY on the
         * first NULL-filter rust file (the amplifier files) inside cbm_parallel_resolve
         * — repos whose rust files all filter to subsets never pay the build/RSS. */
    }
    cbm_log_info("pass.timing", "pass", "lsp_cross_prepare", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    log_phase_mem("lsp_cross_prepare");
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    rc = cbm_parallel_resolve(ctx, files, file_count, cache, &shared_ids, worker_count, all_defs,
                              def_count, def_modules, module_def_index, &cross_registries);
    cbm_log_info("pass.timing", "pass", "parallel_resolve", "elapsed_ms",
                 itoa_buf((int)elapsed_ms(*t)));
    log_phase_mem("parallel_resolve");
    cbm_pxc_free_module_def_index(module_def_index);
    cbm_arena_destroy(&cross_lsp_arena); /* releases all per-lang registries */
    free(all_defs);
    if (def_modules) {
        for (int i = 0; i < file_count; i++) {
            free(def_modules[i]);
        }
        free(def_modules);
    }
    cbm_gbuf_set_next_id(p->gbuf, atomic_load(&shared_ids));
    cbm_pipeline_extract_infra_routes(p->gbuf, files, cache, file_count);
    cbm_pipeline_process_infra_bindings(p->gbuf, files, cache, file_count);
    for (int i = 0; i < file_count; i++) {
        if (cache[i]) {
            cbm_free_result(cache[i]);
        }
    }
    free(cache);
    if (rc != 0) {
        return rc;
    }
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    cbm_pipeline_pass_k8s(ctx, files, file_count);
    cbm_log_info("pass.timing", "pass", "k8s", "elapsed_ms", itoa_buf((int)elapsed_ms(*t)));
    return check_cancel(p) ? CBM_NOT_FOUND : 0;
}

static bool sha256_hex_is_valid(const char *digest) {
    if (!digest || strlen(digest) != CBM_SHA256_HEX_LEN) {
        return false;
    }
    for (int i = 0; i < CBM_SHA256_HEX_LEN; i++) {
        if (!((digest[i] >= '0' && digest[i] <= '9') || (digest[i] >= 'a' && digest[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool trusted_auxiliary_hashes_match(const cbm_pipeline_t *p, const cbm_file_hash_t *stored,
                                           int stored_count) {
    if (!p || !p->git_tracked_only) {
        return true;
    }
    CBMHashTable *stored_by_path =
        cbm_ht_create(stored_count > 0 ? (uint32_t)stored_count * PAIR_LEN : CBM_SZ_64);
    CBMHashTable *current_aux = cbm_ht_create(
        p->auxiliary_file_count > 0 ? (uint32_t)p->auxiliary_file_count * PAIR_LEN : CBM_SZ_64);
    if (!stored_by_path || !current_aux) {
        cbm_ht_free(stored_by_path);
        cbm_ht_free(current_aux);
        return false;
    }
    for (int i = 0; i < stored_count; i++) {
        cbm_ht_set(stored_by_path, stored[i].rel_path, (void *)&stored[i]);
    }
    bool matches = true;
    for (int i = 0; i < p->auxiliary_file_count; i++) {
        const char *rel_path = p->auxiliary_files[i].rel_path;
        cbm_ht_set(current_aux, rel_path, (void *)&p->auxiliary_files[i]);
        const cbm_file_hash_t *old = cbm_ht_get(stored_by_path, rel_path);
        if (!old || !sha256_hex_is_valid(old->sha256) ||
            strcmp(old->sha256, p->auxiliary_snapshots[i].sha256) != 0) {
            matches = false;
        }
    }
    for (int i = 0; matches && i < stored_count; i++) {
        if (is_graph_auxiliary_path_eligible(stored[i].rel_path) &&
            !cbm_ht_get(current_aux, stored[i].rel_path)) {
            matches = false;
        }
    }
    cbm_ht_free(stored_by_path);
    cbm_ht_free(current_aux);
    return matches;
}

static bool trusted_source_hashes_match(const cbm_pipeline_t *p, const cbm_file_info_t *files,
                                        int file_count, const cbm_file_snapshot_t *snapshots,
                                        const cbm_file_hash_t *stored, int stored_count) {
    if (!p || !p->git_tracked_only || file_count < 0 ||
        (file_count > 0 && (!files || !snapshots))) {
        return false;
    }
    CBMHashTable *stored_by_path =
        cbm_ht_create(stored_count > 0 ? (uint32_t)stored_count * PAIR_LEN : CBM_SZ_64);
    CBMHashTable *current_source =
        cbm_ht_create(file_count > 0 ? (uint32_t)file_count * PAIR_LEN : CBM_SZ_64);
    if (!stored_by_path || !current_source) {
        cbm_ht_free(stored_by_path);
        cbm_ht_free(current_source);
        return false;
    }
    for (int i = 0; i < stored_count; i++) {
        cbm_ht_set(stored_by_path, stored[i].rel_path, (void *)&stored[i]);
    }
    bool matches = true;
    for (int i = 0; i < file_count; i++) {
        cbm_ht_set(current_source, files[i].rel_path, (void *)&files[i]);
        const cbm_file_hash_t *old = cbm_ht_get(stored_by_path, files[i].rel_path);
        if (!old || !sha256_hex_is_valid(old->sha256) ||
            strcmp(old->sha256, snapshots[i].sha256) != 0) {
            matches = false;
        }
    }
    for (int i = 0; matches && i < stored_count; i++) {
        if (!cbm_ht_get(current_source, stored[i].rel_path) &&
            !cbm_pipeline_path_is_auxiliary(p, stored[i].rel_path) &&
            /* A legacy generation may contain a hash for a recognized
             * manifest that the canonical depth/skip predicate now excludes.
             * Such an input cannot shape the current graph, so it must not
             * poison admission forever. Eligible auxiliaries are checked by
             * trusted_auxiliary_hashes_match above. */
            !is_graph_auxiliary_path(stored[i].rel_path)) {
            matches = false;
        }
    }
    cbm_ht_free(stored_by_path);
    cbm_ht_free(current_source);
    return matches;
}

static bool trusted_coverage_matches(const cbm_pipeline_t *p, cbm_store_t *store) {
    if (!p || !store || !p->git_tracked_only) {
        return false;
    }
    cbm_coverage_meta_t meta = {0};
    cbm_project_t project = {0};
    bool meta_loaded = cbm_store_coverage_meta_get(store, p->project_name, &meta) == CBM_STORE_OK;
    bool project_loaded = cbm_store_get_project(store, p->project_name, &project) == CBM_STORE_OK;
    bool meta_matches = meta_loaded && project_loaded && meta.generation && project.indexed_at &&
                        strcmp(meta.generation, project.indexed_at) == 0 && meta.index_mode &&
                        strcmp(meta.index_mode, "full") == 0 && meta.recording_status &&
                        strcmp(meta.recording_status, "complete") == 0 &&
                        meta.coverage_version == 1 && meta.hash_records_complete &&
                        p->ignored_total == p->ignored_count &&
                        meta.ignored_files_stored == p->ignored_count &&
                        meta.ignored_files_total == p->ignored_total;
    cbm_store_coverage_meta_clear(&meta);
    if (project_loaded) {
        cbm_project_free_fields(&project);
    }
    if (!meta_matches) {
        return false;
    }

    cbm_coverage_row_t *coverage = NULL;
    int coverage_count = 0;
    if (cbm_store_coverage_get(store, p->project_name, &coverage, &coverage_count) !=
        CBM_STORE_OK) {
        return false;
    }
    CBMHashTable *current =
        cbm_ht_create(p->ignored_count > 0 ? (uint32_t)p->ignored_count * PAIR_LEN : CBM_SZ_64);
    if (!current) {
        cbm_store_free_coverage(coverage, coverage_count);
        return false;
    }
    for (int i = 0; i < p->ignored_count; i++) {
        cbm_ht_set(current, p->ignored_files[i].rel_path, (void *)&p->ignored_files[i]);
    }
    int stored_exact = 0;
    bool matches = true;
    for (int i = 0; i < coverage_count; i++) {
        if (!coverage[i].kind || strcmp(coverage[i].kind, "not_indexed_file") != 0 ||
            !coverage[i].rel_path || !cbm_ht_get(current, coverage[i].rel_path)) {
            matches = false;
            continue;
        }
        stored_exact++;
    }
    matches = matches && coverage_count == p->ignored_count && stored_exact == p->ignored_count;
    cbm_ht_free(current);
    cbm_store_free_coverage(coverage, coverage_count);
    return matches;
}

static bool trusted_branch_identity_matches(const cbm_pipeline_t *p, cbm_store_t *store) {
    if (!p || !store || !p->branch_qn) {
        return false;
    }
    sqlite3 *db = cbm_store_get_db(store);
    sqlite3_stmt *stmt = NULL;
    static const char sql[] = "SELECT COUNT(*), "
                              "SUM(CASE WHEN qualified_name=?2 THEN 1 ELSE 0 END) "
                              "FROM nodes WHERE project=?1 AND label='Branch';";
    if (!db || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(stmt, 1, p->project_name, -1, NULL);
    sqlite3_bind_text(stmt, 2, p->branch_qn, -1, NULL);
    bool matches = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        matches = sqlite3_column_int(stmt, 0) == 1 && sqlite3_column_int(stmt, 1) == 1;
    }
    sqlite3_finalize(stmt);
    return matches && project_active_branch_matches(p, store);
}

static int finalize_trusted_source_classification(cbm_pipeline_t *p, cbm_file_info_t *files,
                                                  cbm_file_snapshot_t *snapshots, int *file_count);

struct cbm_trusted_snapshot {
    cbm_pipeline_t *pipeline;
    cbm_file_info_t *files;
    cbm_file_snapshot_t *snapshots;
    int file_count;
};

void cbm_pipeline_trusted_snapshot_free(cbm_trusted_snapshot_t *snapshot) {
    if (!snapshot) {
        return;
    }
    cbm_discover_free(snapshot->files, snapshot->file_count);
    free(snapshot->snapshots);
    cbm_pipeline_free(snapshot->pipeline);
    free(snapshot);
}

int cbm_pipeline_trusted_snapshot_admit(const char *repo_path, const char *project,
                                        cbm_store_t *store, cbm_trusted_snapshot_t **out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    if (!repo_path || !project || !store || !cbm_store_check_integrity(store)) {
        return CBM_NOT_FOUND;
    }
    cbm_trusted_snapshot_t *admission = (cbm_trusted_snapshot_t *)calloc(1, sizeof(*admission));
    if (!admission) {
        return CBM_NOT_FOUND;
    }
    cbm_pipeline_t *p = cbm_pipeline_new(repo_path, NULL, CBM_MODE_FULL);
    cbm_file_info_t *files = NULL;
    cbm_file_snapshot_t *snapshots = NULL;
    cbm_file_hash_t *hashes = NULL;
    int file_count = 0;
    int hash_count = 0;
    bool matches = false;
    /* cbm_pipeline_new() already captured the admission-start Git context.
     * Re-resolving it here spawned seven redundant Git processes without
     * strengthening the boundary; verify_git_snapshot() below is the required
     * post-corpus comparison against that start snapshot. */
    if (!p || !p->git_tracked_only || !cbm_pipeline_set_project_name(p, project)) {
        goto cleanup;
    }
    p->trusted_validation_only = true;
    if (discover_tracked_files(p, &files, &file_count) != 0 ||
        cbm_pipeline_capture_file_snapshots(p, files, file_count, &snapshots) != 0 ||
        finalize_trusted_source_classification(p, files, snapshots, &file_count) != 0 ||
        cbm_store_get_file_hashes(store, p->project_name, &hashes, &hash_count) != CBM_STORE_OK) {
        goto cleanup;
    }
    matches = trusted_source_hashes_match(p, files, file_count, snapshots, hashes, hash_count) &&
              trusted_auxiliary_hashes_match(p, hashes, hash_count) &&
              trusted_coverage_matches(p, store) && trusted_branch_identity_matches(p, store) &&
              !cbm_pipeline_branch_metadata_changed(p, store) && pipeline_recipe_unchanged(p) &&
              cbm_pipeline_verify_git_snapshot(p) == 0;

cleanup:
    cbm_store_free_file_hashes(hashes, hash_count);
    if (!matches) {
        cbm_discover_free(files, file_count);
        free(snapshots);
        cbm_pipeline_free(p);
        free(admission);
        return CBM_NOT_FOUND;
    }
    admission->pipeline = p;
    admission->files = files;
    admission->snapshots = snapshots;
    admission->file_count = file_count;
    *out = admission;
    return 0;
}

bool cbm_pipeline_trusted_snapshot_verify(cbm_trusted_snapshot_t *snapshot) {
    cbm_pipeline_t *p = snapshot ? snapshot->pipeline : NULL;
    return p && pipeline_recipe_unchanged(p) && cbm_pipeline_verify_git_snapshot(p) == 0 &&
           cbm_pipeline_verify_file_snapshots(p, snapshot->files, snapshot->file_count,
                                              snapshot->snapshots) == 0 &&
           cbm_pipeline_verify_file_snapshots(p, p->auxiliary_files, p->auxiliary_file_count,
                                              p->auxiliary_snapshots) == 0;
}

bool cbm_pipeline_trusted_snapshot_matches_store(const char *repo_path, const char *project,
                                                 cbm_store_t *store) {
    cbm_trusted_snapshot_t *snapshot = NULL;
    bool matches = cbm_pipeline_trusted_snapshot_admit(repo_path, project, store, &snapshot) == 0 &&
                   cbm_pipeline_trusted_snapshot_verify(snapshot) &&
                   cbm_store_strict_snapshot_valid(store);
    cbm_pipeline_trusted_snapshot_free(snapshot);
    return matches;
}

/* Try incremental pipeline or delete old DB for reindex.
 * Returns >= 0 if incremental was used (the return code), or -1 to proceed with full. */
static int try_incremental_or_delete_db(cbm_pipeline_t *p, cbm_file_info_t *files, int file_count,
                                        cbm_file_snapshot_t *snapshots) {
    char *db_path = resolve_db_path(p);
    if (!db_path) {
        return CBM_NOT_FOUND;
    }
    struct stat db_st;
    if (stat(db_path, &db_st) != 0) {
        free(db_path);
        return CBM_NOT_FOUND;
    }
    cbm_store_t *check_store = cbm_store_open_path(db_path);
    if (check_store && cbm_store_check_integrity(check_store)) {
        cbm_file_hash_t *hashes = NULL;
        int hash_count = 0;
        bool hashes_loaded = cbm_store_get_file_hashes(check_store, p->project_name, &hashes,
                                                       &hash_count) == CBM_STORE_OK;
        bool branch_identity_requires_full = !trusted_branch_identity_matches(p, check_store);
        bool trust_requires_full =
            p->git_tracked_only &&
            (!hashes_loaded ||
             !trusted_source_hashes_match(p, files, file_count, snapshots, hashes, hash_count) ||
             !trusted_auxiliary_hashes_match(p, hashes, hash_count) ||
             !trusted_coverage_matches(p, check_store) || branch_identity_requires_full ||
             cbm_pipeline_branch_metadata_changed(p, check_store));
        cbm_store_free_file_hashes(hashes, hash_count);
        cbm_store_close(check_store);
        /* The only trusted no-op gate runs against the published DB before
         * staging is created. Reaching a staging DB means that gate failed,
         * so trust mode must rebuild rather than replace the final DB with a
         * byte-equivalent backup. */
        trust_requires_full = trust_requires_full || p->git_tracked_only;
        if (!trust_requires_full && !branch_identity_requires_full && hash_count > 0 &&
            file_count <= hash_count + (hash_count / PAIR_LEN)) {
            cbm_log_info("pipeline.route", "path", "incremental", "stored_hashes",
                         itoa_buf(hash_count));
            int rc = cbm_pipeline_run_incremental(p, db_path, files, file_count);
            free(db_path);
            return rc;
        }
        if (trust_requires_full) {
            cbm_log_info("pipeline.route", "path", "trusted_input_change_reindex");
        }
        if (branch_identity_requires_full) {
            cbm_log_info("pipeline.route", "path", "branch_change_reindex");
        }
        if (hash_count > 0) {
            cbm_log_info("pipeline.route", "path", "mode_change_reindex", "stored_hashes",
                         itoa_buf(hash_count), "discovered", itoa_buf(file_count));
        }
    } else if (check_store) {
        cbm_store_close(check_store);
    }
    cbm_log_info("pipeline.route", "path", "reindex", "action", "deleting old db");
    /* Capture any ADR before deleting the DB so the full-reindex rebuild can
     * restore it (project_summaries is otherwise lost). Issue #516. */
    {
        cbm_store_t *adr_store = cbm_store_open_path(db_path);
        if (adr_store) {
            cbm_adr_t existing;
            if (cbm_store_adr_get(adr_store, p->project_name, &existing) == CBM_STORE_OK) {
                if (existing.content) {
                    free(p->saved_adr);
                    p->saved_adr = strdup(existing.content);
                }
                cbm_store_adr_free(&existing);
            }
            cbm_store_close(adr_store);
        }
    }
    (void)cbm_unlink(db_path);
    (void)cbm_remove_db_sidecars(db_path);
    free(db_path);
    return CBM_NOT_FOUND;
}

/* Get platform-specific mtime in nanoseconds. */
static int64_t stat_mtime_ns(const struct stat *fst) {
#ifdef __APPLE__
    return ((int64_t)fst->st_mtimespec.tv_sec * PL_NSEC_PER_SEC) +
           (int64_t)fst->st_mtimespec.tv_nsec;
#elif defined(_WIN32)
    return (int64_t)fst->st_mtime * 1000000000LL;
#else
    return ((int64_t)fst->st_mtim.tv_sec * PL_NSEC_PER_SEC) + (int64_t)fst->st_mtim.tv_nsec;
#endif
}

static int portable_file_stat(const char *path, struct stat *st) {
#ifdef _WIN32
    wchar_t *wpath = cbm_path_to_wide(path);
    if (!wpath) {
        return CBM_NOT_FOUND;
    }
    struct _stat64 wide_st;
    int rc = _wstat64(wpath, &wide_st);
    free(wpath);
    if (rc != 0) {
        return CBM_NOT_FOUND;
    }
    memset(st, 0, sizeof(*st));
    st->st_mode = wide_st.st_mode;
    st->st_size = wide_st.st_size;
    st->st_mtime = wide_st.st_mtime;
    return 0;
#else
    return stat(path, st);
#endif
}

static bool ensure_trusted_snapshot_dir(cbm_pipeline_t *p) {
    if (!p || !p->git_tracked_only) {
        return false;
    }
    if (p->trusted_snapshot_dir) {
        return true;
    }
    const char *tmp = cbm_tmpdir();
    static const char suffix[] = "/cbm-trusted-snapshot-XXXXXX";
    size_t tmp_len = strlen(tmp);
    if (tmp_len > SIZE_MAX - sizeof(suffix)) {
        return false;
    }
    char *dir = (char *)malloc(tmp_len + sizeof(suffix));
    if (!dir) {
        return false;
    }
    snprintf(dir, tmp_len + sizeof(suffix), "%s%s", tmp, suffix);
    if (!cbm_mkdtemp(dir)) {
        free(dir);
        return false;
    }
#ifdef _WIN32
    wchar_t *wide = cbm_path_to_wide(dir);
    HANDLE handle =
        wide ? CreateFileW(wide, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
             : INVALID_HANDLE_VALUE;
    free(wide);
    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    BY_HANDLE_FILE_INFORMATION identity = {0};
    bool anchored = handle != INVALID_HANDLE_VALUE &&
                    GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) &&
                    !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                    (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    GetFileInformationByHandle(handle, &identity);
    if (!anchored) {
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
        (void)cbm_rmdir(dir);
        free(dir);
        return false;
    }
    p->trusted_snapshot_dir_handle = handle;
    p->trusted_snapshot_dir_identity = identity;
#else
    int flags = O_RDONLY | O_DIRECTORY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(dir, flags);
    struct stat status;
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode)) {
        if (fd >= 0) {
            close(fd);
        }
        (void)cbm_rmdir(dir);
        free(dir);
        return false;
    }
    p->trusted_snapshot_dir_fd = fd;
    p->trusted_snapshot_dir_device = status.st_dev;
    p->trusted_snapshot_dir_inode = status.st_ino;
#endif
    p->trusted_snapshot_dir = dir;
    return true;
}

static bool trusted_snapshot_dir_matches(const cbm_pipeline_t *p) {
    if (!p || !p->trusted_snapshot_dir) {
        return false;
    }
#ifdef _WIN32
    wchar_t *wide = cbm_path_to_wide(p->trusted_snapshot_dir);
    HANDLE probe =
        wide ? CreateFileW(wide, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
             : INVALID_HANDLE_VALUE;
    free(wide);
    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    BY_HANDLE_FILE_INFORMATION identity = {0};
    bool matches =
        probe != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandleEx(probe, FileAttributeTagInfo, &tag, sizeof(tag)) &&
        !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        GetFileInformationByHandle(probe, &identity) &&
        identity.dwVolumeSerialNumber == p->trusted_snapshot_dir_identity.dwVolumeSerialNumber &&
        identity.nFileIndexHigh == p->trusted_snapshot_dir_identity.nFileIndexHigh &&
        identity.nFileIndexLow == p->trusted_snapshot_dir_identity.nFileIndexLow;
    if (probe != INVALID_HANDLE_VALUE) {
        CloseHandle(probe);
    }
    return matches;
#else
    int flags = O_RDONLY | O_DIRECTORY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int probe = open(p->trusted_snapshot_dir, flags);
    struct stat status;
    bool matches = probe >= 0 && fstat(probe, &status) == 0 && S_ISDIR(status.st_mode) &&
                   status.st_dev == p->trusted_snapshot_dir_device &&
                   status.st_ino == p->trusted_snapshot_dir_inode;
    if (probe >= 0) {
        close(probe);
    }
    return matches;
#endif
}

static bool seal_trusted_snapshot_dir(cbm_pipeline_t *p) {
    if (!p || p->trusted_validation_only || !p->trusted_snapshot_dir) {
        return true;
    }
    if (!trusted_snapshot_dir_matches(p)) {
        return false;
    }
#ifdef _WIN32
    wchar_t *wide = cbm_path_to_wide(p->trusted_snapshot_dir);
    DWORD attributes = wide ? GetFileAttributesW(wide) : INVALID_FILE_ATTRIBUTES;
    bool ok = attributes != INVALID_FILE_ATTRIBUTES &&
              SetFileAttributesW(wide, attributes | FILE_ATTRIBUTE_READONLY);
    free(wide);
    return ok;
#else
    return chmod(p->trusted_snapshot_dir, 0500) == 0;
#endif
}

/* Store captured bytes in one owner-private scratch directory. Files are
 * closed immediately and made read-only, so descriptor/handle usage stays
 * O(1) even for very large repositories. The directory is sealed before any
 * parser consumes it and every copy is rehashed at dump/publish boundaries. */
static char *write_trusted_snapshot_copy(cbm_pipeline_t *p, const cbm_file_info_t *file,
                                         const unsigned char *data, size_t len) {
    if (!p || !file || !file->rel_path || (!data && len > 0) || !ensure_trusted_snapshot_dir(p) ||
        !trusted_snapshot_dir_matches(p)) {
        return NULL;
    }
    const char *basename = strrchr(file->rel_path, '/');
    basename = basename ? basename + 1 : file->rel_path;
    const char *extension = strrchr(basename, '.');
    if (!extension || strlen(extension) > CBM_SZ_32) {
        extension = "";
    }
    size_t dir_len = strlen(p->trusted_snapshot_dir);
    size_t extension_len = strlen(extension);
    if (dir_len > SIZE_MAX - extension_len - CBM_SZ_32) {
        return NULL;
    }
    size_t path_size = dir_len + extension_len + CBM_SZ_32;
    char *path = (char *)malloc(path_size);
    if (!path) {
        return NULL;
    }
    unsigned int serial = p->trusted_snapshot_serial++;
    char internal_name[CBM_SZ_64];
    int internal_n = snprintf(internal_name, sizeof(internal_name), "%08x%s", serial, extension);
    int n = internal_n > 0 && (size_t)internal_n < sizeof(internal_name)
                ? snprintf(path, path_size, "%s/%s", p->trusted_snapshot_dir, internal_name)
                : CBM_NOT_FOUND;
    if (n < 0 || (size_t)n >= path_size) {
        free(path);
        return NULL;
    }
#ifdef _WIN32
    wchar_t *wide_path = cbm_path_to_wide(path);
    HANDLE handle = wide_path
                        ? CreateFileW(wide_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                                      NULL, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL)
                        : INVALID_HANDLE_VALUE;
    free(wide_path);
    if (handle == INVALID_HANDLE_VALUE) {
        free(path);
        return NULL;
    }
    size_t written = 0;
    bool ok = true;
    while (written < len) {
        DWORD chunk = (DWORD)((len - written) > UINT32_MAX ? UINT32_MAX : (len - written));
        DWORD count = 0;
        if (!WriteFile(handle, data + written, chunk, &count, NULL) || count == 0) {
            ok = false;
            break;
        }
        written += count;
    }
    BY_HANDLE_FILE_INFORMATION identity = {0};
    ok = ok && written == len && GetFileInformationByHandle(handle, &identity) &&
         !(identity.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && identity.nNumberOfLinks == 1;
    CloseHandle(handle);
    handle = INVALID_HANDLE_VALUE;
    wide_path = cbm_path_to_wide(path);
    ok = ok && wide_path &&
         SetFileAttributesW(wide_path, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_TEMPORARY);
    free(wide_path);
    if (!ok) {
        (void)cbm_unlink(path);
        free(path);
        return NULL;
    }
    return path;
#else
    int flags = O_CREAT | O_EXCL | O_WRONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = openat(p->trusted_snapshot_dir_fd, internal_name, flags, 0600);
    if (fd < 0) {
        free(path);
        return NULL;
    }
    size_t written = 0;
    bool ok = true;
    while (written < len) {
        ssize_t count = write(fd, data + written, len - written);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            ok = false;
            break;
        }
        written += (size_t)count;
    }
    struct stat status;
    ok = ok && written == len && fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
         status.st_nlink == 1 && fchmod(fd, 0400) == 0;
    if (close(fd) != 0) {
        ok = false;
    }
    if (!ok) {
        (void)cbm_unlink(path);
        free(path);
        return NULL;
    }
#ifdef __linux__
    int pseudo_len =
        snprintf(NULL, 0, "/proc/self/fd/%d/%s", p->trusted_snapshot_dir_fd, internal_name);
    char *pseudo = pseudo_len >= 0 ? (char *)malloc((size_t)pseudo_len + 1) : NULL;
    if (!pseudo) {
        free(path);
        return NULL;
    }
    snprintf(pseudo, (size_t)pseudo_len + 1, "/proc/self/fd/%d/%s", p->trusted_snapshot_dir_fd,
             internal_name);
    free(path);
    return pseudo;
#else
    return path;
#endif
#endif
}

static int trusted_auxiliary_index(const cbm_pipeline_t *p, const char *rel_path) {
    if (!p || !rel_path || !p->auxiliary_files) {
        return CBM_NOT_FOUND;
    }
    int lo = 0;
    int hi = p->auxiliary_file_count - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / PAIR_LEN;
        int cmp = strcmp(rel_path, p->auxiliary_files[mid].rel_path);
        if (cmp == 0) {
            return mid;
        }
        if (cmp < 0) {
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }
    return CBM_NOT_FOUND;
}

static int capture_one_file_snapshot(cbm_pipeline_t *p, cbm_file_info_t *file,
                                     cbm_file_snapshot_t *snapshot) {
    if (!p || !file || !file->path || !file->rel_path || !snapshot) {
        return CBM_NOT_FOUND;
    }
    if (p->git_tracked_only) {
        int auxiliary_index =
            p->auxiliary_snapshots ? trusted_auxiliary_index(p, file->rel_path) : CBM_NOT_FOUND;
        if (!p->trusted_validation_only && auxiliary_index >= 0 &&
            &p->auxiliary_files[auxiliary_index] != file) {
            char *shared_path = strdup(p->auxiliary_files[auxiliary_index].path);
            if (!shared_path) {
                return CBM_NOT_FOUND;
            }
            if (file->language != CBM_LANG_COUNT) {
                const char *basename = strrchr(file->rel_path, '/');
                basename = basename ? basename + 1 : file->rel_path;
                file->language = cbm_discover_detect_file_language(
                    basename, p->auxiliary_files[auxiliary_index].path);
            }
            free(file->path);
            file->path = shared_path;
            file->size = p->auxiliary_files[auxiliary_index].size;
            *snapshot = p->auxiliary_snapshots[auxiliary_index];
            return 0;
        }
        unsigned char *bytes = NULL;
        size_t byte_count = 0;
        struct stat status;
        long configured_limit = cbm_max_file_bytes();
        size_t max_bytes = configured_limit > 0 ? (size_t)configured_limit : SIZE_MAX;
        if (!p->trusted_root ||
            cbm_trusted_root_read_file(p->trusted_root, file->rel_path, max_bytes, &bytes,
                                       &byte_count, &status) != 0) {
            cbm_log_error("pipeline.snapshot", "status", "unreadable_tracked_file", "rel_path",
                          file->rel_path);
            return CBM_NOT_FOUND;
        }
        if (file->language != CBM_LANG_COUNT) {
            const char *basename = strrchr(file->rel_path, '/');
            basename = basename ? basename + 1 : file->rel_path;
            file->language = cbm_discover_detect_file_language_bytes(basename, bytes, byte_count);
        }
        cbm_sha256_hex(bytes, byte_count, snapshot->sha256);
        char *copy = NULL;
        if (!p->trusted_validation_only) {
            copy = write_trusted_snapshot_copy(p, file, bytes, byte_count);
            if (!copy) {
                free(bytes);
                return CBM_NOT_FOUND;
            }
        }
        free(bytes);
        if (copy) {
            free(file->path);
            file->path = copy;
        }
        file->size = (int64_t)byte_count;
        snapshot->mtime_ns = stat_mtime_ns(&status);
        snapshot->size = (int64_t)byte_count;
        return 0;
    }
    struct stat before;
    struct stat after;
    int before_rc = portable_file_stat(file->path, &before);
    int hash_rc = before_rc == 0 ? cbm_sha256_file(file->path, snapshot->sha256) : CBM_NOT_FOUND;
    int after_rc = portable_file_stat(file->path, &after);
    if (before_rc != 0 || hash_rc != 0 || after_rc != 0 ||
        stat_mtime_ns(&before) != stat_mtime_ns(&after) || before.st_size != after.st_size) {
        cbm_log_error("pipeline.snapshot", "status", "unstable_or_unreadable", "rel_path",
                      file->rel_path);
        return CBM_NOT_FOUND;
    }
    snapshot->mtime_ns = stat_mtime_ns(&after);
    snapshot->size = after.st_size;
    return 0;
}

static int finalize_trusted_source_classification(cbm_pipeline_t *p, cbm_file_info_t *files,
                                                  cbm_file_snapshot_t *snapshots, int *file_count) {
    if (!p || !file_count || *file_count < 0) {
        return CBM_NOT_FOUND;
    }
    if (*file_count == 0) {
        return 0;
    }
    if (!files || !snapshots) {
        return CBM_NOT_FOUND;
    }
    int kept = 0;
    for (int i = 0; i < *file_count; i++) {
        if (files[i].language == CBM_LANG_COUNT) {
            if (!cbm_pipeline_path_is_auxiliary(p, files[i].rel_path) &&
                add_tracked_discovery_exclusion(p, files[i].rel_path) != 0) {
                return CBM_NOT_FOUND;
            }
            free(files[i].path);
            free(files[i].rel_path);
            memset(&files[i], 0, sizeof(files[i]));
            continue;
        }
        if (kept != i) {
            files[kept] = files[i];
            snapshots[kept] = snapshots[i];
            memset(&files[i], 0, sizeof(files[i]));
            memset(&snapshots[i], 0, sizeof(snapshots[i]));
        }
        kept++;
    }
    *file_count = kept;
    return 0;
}

int cbm_pipeline_capture_file_snapshots(cbm_pipeline_t *p, cbm_file_info_t *files, int file_count,
                                        cbm_file_snapshot_t **out) {
    if (!p || !out || file_count < 0 || (file_count > 0 && !files)) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    if (file_count == 0) {
        return 0;
    }
    cbm_file_snapshot_t *snapshots =
        (cbm_file_snapshot_t *)calloc((size_t)file_count, sizeof(*snapshots));
    if (!snapshots) {
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        if (capture_one_file_snapshot(p, &files[i], &snapshots[i]) != 0) {
            free(snapshots);
            return CBM_NOT_FOUND;
        }
    }
    *out = snapshots;
    return 0;
}

int cbm_pipeline_verify_file_snapshots(const cbm_pipeline_t *p, const cbm_file_info_t *files,
                                       int file_count, cbm_file_snapshot_t *snapshots) {
    if (!p || file_count < 0 || (file_count > 0 && (!files || !snapshots))) {
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        cbm_file_snapshot_t final_snapshot = {0};
        int capture_rc = CBM_NOT_FOUND;
        if (p->git_tracked_only && p->trusted_root && files[i].rel_path) {
            unsigned char *bytes = NULL;
            size_t byte_count = 0;
            struct stat status;
            long configured_limit = cbm_max_file_bytes();
            size_t max_bytes = configured_limit > 0 ? (size_t)configured_limit : SIZE_MAX;
            if (cbm_trusted_root_read_file(p->trusted_root, files[i].rel_path, max_bytes, &bytes,
                                           &byte_count, &status) == 0) {
                cbm_sha256_hex(bytes, byte_count, final_snapshot.sha256);
                final_snapshot.mtime_ns = stat_mtime_ns(&status);
                final_snapshot.size = (int64_t)byte_count;
                capture_rc = 0;
            }
            free(bytes);
        } else {
            struct stat before;
            struct stat after;
            if (portable_file_stat(files[i].path, &before) == 0 &&
                cbm_sha256_file(files[i].path, final_snapshot.sha256) == 0 &&
                portable_file_stat(files[i].path, &after) == 0 &&
                stat_mtime_ns(&before) == stat_mtime_ns(&after) &&
                before.st_size == after.st_size) {
                final_snapshot.mtime_ns = stat_mtime_ns(&after);
                final_snapshot.size = after.st_size;
                capture_rc = 0;
            }
        }
        if (capture_rc != 0 || strcmp(final_snapshot.sha256, snapshots[i].sha256) != 0) {
            cbm_log_error("pipeline.snapshot", "status", "content_changed_during_index", "rel_path",
                          files[i].rel_path ? files[i].rel_path : "");
            return CBM_NOT_FOUND;
        }
        /* Content is identical to the pre-extraction digest. Refresh only
         * metadata so a harmless touch during indexing does not force the
         * next run to reparse the file. */
        snapshots[i].mtime_ns = final_snapshot.mtime_ns;
        snapshots[i].size = final_snapshot.size;
    }
    return 0;
}

static int verify_captured_parser_snapshots(const cbm_pipeline_t *p, const cbm_file_info_t *files,
                                            int file_count, const cbm_file_snapshot_t *snapshots) {
    if (!p || file_count < 0 || (file_count > 0 && (!files || !snapshots))) {
        return CBM_NOT_FOUND;
    }
    if (!p->git_tracked_only || p->trusted_validation_only) {
        return 0;
    }
    if (file_count == 0) {
        return 0;
    }
    if (!trusted_snapshot_dir_matches(p)) {
        return CBM_NOT_FOUND;
    }
    for (int i = 0; i < file_count; i++) {
        char digest[CBM_SHA256_HEX_LEN + 1];
        if (!files[i].path || cbm_sha256_file(files[i].path, digest) != 0 ||
            strcmp(digest, snapshots[i].sha256) != 0) {
            cbm_log_error("pipeline.snapshot", "status", "captured_bytes_changed", "rel_path",
                          files[i].rel_path ? files[i].rel_path : "");
            return CBM_NOT_FOUND;
        }
    }
    return 0;
}

static const char *pipeline_mode_name(cbm_index_mode_t mode) {
    switch (mode) {
    case CBM_MODE_FULL:
        return "full";
    case CBM_MODE_MODERATE:
        return "moderate";
    case CBM_MODE_FAST:
        return "fast";
    default:
        return "unknown";
    }
}

/* Dump graph to SQLite and persist file hashes for incremental indexing. */
static int dump_and_persist_hashes(cbm_pipeline_t *p, const cbm_file_info_t *files, int file_count,
                                   cbm_file_snapshot_t *snapshots, struct timespec *t) {
    cbm_clock_gettime(CLOCK_MONOTONIC, t);
    if (p->git_tracked_only &&
        (!pipeline_recipe_unchanged(p) || cbm_pipeline_verify_git_snapshot(p) != 0 ||
         verify_captured_parser_snapshots(p, files, file_count, snapshots) != 0 ||
         verify_captured_parser_snapshots(p, p->auxiliary_files, p->auxiliary_file_count,
                                          p->auxiliary_snapshots) != 0 ||
         cbm_pipeline_verify_file_snapshots(p, files, file_count, snapshots) != 0 ||
         cbm_pipeline_verify_file_snapshots(p, p->auxiliary_files, p->auxiliary_file_count,
                                            p->auxiliary_snapshots) != 0)) {
        cbm_log_error("pipeline.err", "phase", "snapshot_verify");
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }
    char *db_path = resolve_db_path(p);
    if (!db_path) {
        return CBM_NOT_FOUND;
    }
    char *db_dir = strdup(db_path);
    if (!db_dir) {
        free(db_path);
        return CBM_NOT_FOUND;
    }
    char *last_slash = strrchr(db_dir, '/');
#ifdef _WIN32
    char *last_backslash = strrchr(db_dir, '\\');
    if (last_backslash && (!last_slash || last_backslash > last_slash)) {
        last_slash = last_backslash;
    }
#endif
    if (last_slash) {
        *last_slash = '\0';
        cbm_mkdir_p(db_dir, CBM_DIR_PERMS);
    }
    free(db_dir);
    /* Capture committed counts BEFORE the dump. cbm_gbuf_dump_to_sqlite calls
     * release_gbuf_indexes(), which frees node_by_qn (graph_buffer.c), after
     * which cbm_gbuf_node_count() returns 0. Reading these post-dump left
     * committed_nodes at 0, so the #334 plausibility gate never fired. */
    p->committed_nodes = cbm_gbuf_node_count(p->gbuf);
    p->committed_edges = cbm_gbuf_edge_count(p->gbuf);
    int rc = cbm_gbuf_dump_to_sqlite(p->gbuf, db_path);
    if (rc != 0) {
        cbm_log_error("pipeline.err", "phase", "dump");
        free(db_path);
        return rc;
    }
    cbm_log_info("pass.timing", "pass", "dump", "elapsed_ms", itoa_buf((int)elapsed_ms(*t)));
    /* Persist-tail spans (phase "persist"): attribute the ~60s that lands here
     * AFTER cbm_gbuf_dump_to_sqlite returns. Active only under CBM_PROFILE. */
    CBM_PROF_START(t_reopen);
    cbm_store_t *hash_store = cbm_store_open_path(db_path);
    CBM_PROF_END("persist", "1_reopen", t_reopen);
    if (!hash_store) {
        cbm_log_error("pipeline.err", "phase", "persist_open", "path", db_path);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    /* The byte writer deliberately omits store_meta. Seed the new file through
     * the existing project choke point so every full rebuild gets a distinct
     * cursor/provenance generation. */
    if (cbm_store_upsert_project(hash_store, p->project_name, p->repo_path) != CBM_STORE_OK) {
        cbm_log_error("pipeline.err", "phase", "persist_generation", "project", p->project_name);
        cbm_store_close(hash_store);
        free(db_path);
        return CBM_NOT_FOUND;
    }
    bool hash_records_complete = true;
    bool trust_persist_ok = true;
    {
        CBM_PROF_START(t_delhash);
        if (cbm_store_delete_file_hashes(hash_store, p->project_name) != CBM_STORE_OK) {
            hash_records_complete = false;
        }
        CBM_PROF_END("persist", "2_delete_file_hashes", t_delhash);

        /* Restore the ADR captured before the dump. Surface a failed restore
         * rather than silently dropping the ADR (the original #516 symptom). */
        CBM_PROF_START(t_adr);
        if (p->saved_adr) {
            if (cbm_store_adr_store(hash_store, p->project_name, p->saved_adr) != CBM_STORE_OK) {
                cbm_log_error("pipeline.err", "phase", "adr_restore", "project", p->project_name);
                if (p->git_tracked_only) {
                    trust_persist_ok = false;
                }
            }
        }
        CBM_PROF_END("persist", "3_adr_restore", t_adr);

        /* Batch file-state rows into one transaction. Default mode retains
         * the legacy mtime/size + empty-digest contract. Trust mode persists
         * the verified pre-extraction SHA for sources plus graph-shaping
         * auxiliary inputs (tracked manifests/tsconfig). */
        CBM_PROF_START(t_fh);
        int hash_capacity = file_count + (p->git_tracked_only ? p->auxiliary_file_count : 0);
        CBMHashTable *source_paths = NULL;
        bool source_paths_ready = true;
        if (p->git_tracked_only && p->auxiliary_file_count > 0) {
            source_paths =
                cbm_ht_create(file_count > 0 ? (uint32_t)file_count * PAIR_LEN : CBM_SZ_64);
            source_paths_ready = source_paths != NULL;
            for (int i = 0; source_paths_ready && i < file_count; i++) {
                cbm_ht_set(source_paths, files[i].rel_path, p);
            }
            source_paths_ready =
                source_paths_ready && (int)cbm_ht_count(source_paths) == file_count;
            if (!source_paths_ready) {
                hash_records_complete = false;
                trust_persist_ok = false;
            }
        }
        cbm_file_hash_t *fhashes = (cbm_file_hash_t *)malloc(
            (size_t)(hash_capacity > 0 ? hash_capacity : 1) * sizeof(cbm_file_hash_t));
        if (fhashes) {
            int fh_n = 0;
            for (int i = 0; i < file_count; i++) {
                if (p->git_tracked_only) {
                    fhashes[fh_n].project = p->project_name;
                    fhashes[fh_n].rel_path = files[i].rel_path;
                    fhashes[fh_n].sha256 = snapshots[i].sha256;
                    fhashes[fh_n].mtime_ns = snapshots[i].mtime_ns;
                    fhashes[fh_n].size = snapshots[i].size;
                    fh_n++;
                } else {
                    struct stat fst;
                    if (stat(files[i].path, &fst) == 0) {
                        fhashes[fh_n].project = p->project_name;
                        fhashes[fh_n].rel_path = files[i].rel_path;
                        fhashes[fh_n].sha256 = "";
                        fhashes[fh_n].mtime_ns = stat_mtime_ns(&fst);
                        fhashes[fh_n].size = fst.st_size;
                        fh_n++;
                    } else {
                        hash_records_complete = false;
                    }
                }
            }
            if (p->git_tracked_only && source_paths_ready) {
                for (int i = 0; i < p->auxiliary_file_count; i++) {
                    if (cbm_ht_has(source_paths, p->auxiliary_files[i].rel_path)) {
                        continue;
                    }
                    fhashes[fh_n].project = p->project_name;
                    fhashes[fh_n].rel_path = p->auxiliary_files[i].rel_path;
                    fhashes[fh_n].sha256 = p->auxiliary_snapshots[i].sha256;
                    fhashes[fh_n].mtime_ns = p->auxiliary_snapshots[i].mtime_ns;
                    fhashes[fh_n].size = p->auxiliary_snapshots[i].size;
                    fh_n++;
                }
            }
            if (cbm_store_upsert_file_hash_batch(hash_store, fhashes, fh_n) != CBM_STORE_OK) {
                cbm_log_error("pipeline.err", "phase", "persist_file_hashes", "project",
                              p->project_name);
                hash_records_complete = false;
            }
            free(fhashes);
        } else {
            /* OOM fallback: identical rows via the per-file path. */
            for (int i = 0; i < file_count; i++) {
                if (p->git_tracked_only) {
                    if (cbm_store_upsert_file_hash(hash_store, p->project_name, files[i].rel_path,
                                                   snapshots[i].sha256, snapshots[i].mtime_ns,
                                                   snapshots[i].size) != CBM_STORE_OK) {
                        hash_records_complete = false;
                    }
                } else {
                    struct stat fst;
                    if (stat(files[i].path, &fst) == 0) {
                        if (cbm_store_upsert_file_hash(hash_store, p->project_name,
                                                       files[i].rel_path, "", stat_mtime_ns(&fst),
                                                       fst.st_size) != CBM_STORE_OK) {
                            hash_records_complete = false;
                        }
                    } else {
                        hash_records_complete = false;
                    }
                }
            }
            if (p->git_tracked_only && source_paths_ready) {
                for (int i = 0; i < p->auxiliary_file_count; i++) {
                    if (!cbm_ht_has(source_paths, p->auxiliary_files[i].rel_path) &&
                        cbm_store_upsert_file_hash(
                            hash_store, p->project_name, p->auxiliary_files[i].rel_path,
                            p->auxiliary_snapshots[i].sha256, p->auxiliary_snapshots[i].mtime_ns,
                            p->auxiliary_snapshots[i].size) != CBM_STORE_OK) {
                        hash_records_complete = false;
                    }
                }
            }
        }
        cbm_ht_free(source_paths);
        CBM_PROF_END_N("persist", "4_file_hashes", t_fh, hash_capacity);

        /* Coverage rows (#963): a full run's file_errors plus the by-design
         * discovery exclusions are the complete coverage truth for the
         * project. The dump recreated the DB file, so the separate
         * index_coverage table starts empty — write only when there is
         * something to record (AFTER hashes, so the deleted-file prune inside
         * replace sees the live file set; not_indexed_* kinds are exempt from
         * that prune — deliberately-unindexed paths have no hash rows). */
        int cov_total = p->file_errors_count + p->excluded_count + p->ignored_count;
        cbm_coverage_row_t *cov = NULL;
        int cn = 0;
        bool coverage_rows_available = cov_total == 0 && !p->error_recording_failed;
        if (cov_total > 0) {
            cov = (cbm_coverage_row_t *)malloc((size_t)cov_total * sizeof(*cov));
            if (cov) {
                coverage_rows_available = true;
                for (int i = 0; i < p->file_errors_count; i++) {
                    cov[cn].rel_path = p->file_errors[i].path;
                    cov[cn].kind = p->file_errors[i].phase;
                    cov[cn].detail = p->file_errors[i].reason;
                    cn++;
                }
                for (int i = 0; i < p->excluded_count; i++) {
                    cov[cn].rel_path = p->excluded_dirs[i];
                    cov[cn].kind = "not_indexed_dir";
                    cov[cn].detail = "excluded subtree";
                    cn++;
                }
                for (int i = 0; i < p->ignored_count; i++) {
                    cov[cn].rel_path = p->ignored_files[i].rel_path;
                    cov[cn].kind = "not_indexed_file";
                    cov[cn].detail = p->ignored_files[i].reason;
                    cn++;
                }
            }
        }

        cbm_project_t project_info = {0};
        bool have_project_info =
            cbm_store_get_project(hash_store, p->project_name, &project_info) == CBM_STORE_OK;
        if (p->git_tracked_only &&
            (p->file_errors_count > 0 || p->error_recording_failed || !coverage_rows_available ||
             !have_project_info || !project_info.indexed_at ||
             p->ignored_total != p->ignored_count)) {
            trust_persist_ok = false;
        }
        const char *recording_status =
            !coverage_rows_available
                ? "unavailable"
                : (p->ignored_total > p->ignored_count ? "truncated" : "complete");
        cbm_coverage_meta_t coverage_meta = {
            .generation = have_project_info ? project_info.indexed_at : NULL,
            .index_mode = pipeline_mode_name(p->mode),
            .recording_status = recording_status,
            .ignored_files_stored = p->ignored_count,
            .ignored_files_total = p->ignored_total,
            .coverage_version = 1,
            .hash_records_complete = hash_records_complete,
        };
        if (cbm_store_coverage_replace_ex(hash_store, p->project_name, cov, cn, &coverage_meta) !=
            CBM_STORE_OK) {
            cbm_log_error("pipeline.err", "phase", "persist_coverage", "project", p->project_name);
            if (p->git_tracked_only) {
                trust_persist_ok = false;
            }
        }
        free(cov);
        if (have_project_info) {
            cbm_project_free_fields(&project_info);
        }
        if (p->ignored_total > p->ignored_count) {
            cbm_log_warn("index.ignored_capped", "stored", itoa_buf(p->ignored_count), "total",
                         itoa_buf(p->ignored_total));
        }

        /* FTS5 backfill: populate nodes_fts with camelCase-split names.
         * Contentless FTS5 requires the special 'delete-all' command instead of
         * DELETE FROM to wipe prior rows (there's no underlying content table).
         * Falls back to plain names if cbm_camel_split is unavailable (which
         * shouldn't happen because we always register it, but we stay defensive). */
        CBM_PROF_START(t_fts);
        bool fts_ok =
            cbm_store_exec(hash_store, "INSERT INTO nodes_fts(nodes_fts) VALUES('delete-all');") ==
            CBM_STORE_OK;
        if (fts_ok &&
            cbm_store_exec(hash_store,
                           "INSERT INTO nodes_fts(rowid, name, qualified_name, label, file_path) "
                           "SELECT id, cbm_camel_split(name), qualified_name, label, file_path "
                           "FROM nodes;") != CBM_STORE_OK) {
            fts_ok = cbm_store_exec(
                         hash_store,
                         "INSERT INTO nodes_fts(rowid, name, qualified_name, label, file_path) "
                         "SELECT id, name, qualified_name, label, file_path FROM nodes;") ==
                     CBM_STORE_OK;
        }
        if (p->git_tracked_only && !fts_ok) {
            trust_persist_ok = false;
        }
        CBM_PROF_END("persist", "5_fts_backfill", t_fts);

        cbm_store_close(hash_store);
        cbm_log_info("pass.timing", "pass", "persist_hashes", "files", itoa_buf(file_count));
    }
    free(p->saved_adr);
    p->saved_adr = NULL;
    free(db_path);

    return p->git_tracked_only && (!hash_records_complete || !trust_persist_ok)
               ? CBM_PIPELINE_ABORT_PRESERVE_DB
               : 0;
}

/* Run githistory pass. */
static int run_githistory(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx) {
    /* The legacy history pass has a wall-clock cutoff and line-delimited
     * filename framing, so it is not a deterministic function of the bound
     * trusted snapshot. Strict mode deliberately omits it; this choice is
     * pinned in the recipe fingerprint. */
    if (p->git_tracked_only) {
        cbm_log_info("pass.skip", "pass", "githistory", "reason", "trusted_snapshot_determinism");
        return 0;
    }
    struct timespec t_gh;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t_gh);

    cbm_githistory_result_t gh_result = {0};
    cbm_thread_t gh_thread;
    bool gh_threaded = false;
    gh_compute_arg_t gh_arg = {.repo_path = ctx->repo_path, .result = &gh_result};

    if (p->mode != CBM_MODE_FAST) {
        if (effective_worker_count(true) > SKIP_ONE) {
            if (cbm_thread_create(&gh_thread, 0, gh_compute_thread_fn, &gh_arg) == 0) {
                gh_threaded = true;
            }
        }
        if (!gh_threaded) {
            cbm_pipeline_githistory_compute(ctx->repo_path, &gh_result);
            cbm_log_info("pass.timing", "pass", "githistory_compute", "elapsed_ms",
                         itoa_buf((int)elapsed_ms(t_gh)));
        }
    } else {
        cbm_log_info("pass.skip", "pass", "githistory", "reason", "fast_mode");
    }

    if (gh_threaded) {
        cbm_thread_join(&gh_thread);
        cbm_log_info("pass.timing", "pass", "githistory_compute", "elapsed_ms",
                     itoa_buf((int)elapsed_ms(t_gh)));
    }

    int gh_edges = 0;
    if (gh_result.count > 0 || gh_result.file_temporal_count > 0) {
        gh_edges = cbm_pipeline_githistory_apply(ctx, &gh_result);
    }
    cbm_log_info("pass.done", "pass", "githistory", "commits", itoa_buf(gh_result.commit_count),
                 "edges", itoa_buf(gh_edges));
    free(gh_result.couplings);
    free(gh_result.file_temporal);
    return 0;
}

/* ── Pipeline run ────────────────────────────────────────────────── */

/* Run tests + git history. Returns 0 on success. */
static int run_tests_and_history(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                 const cbm_file_info_t *files, int file_count) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    CBM_PROF_START(t_tests);
    int rc = cbm_pipeline_pass_tests(ctx, files, file_count);
    CBM_PROF_END_N("pipeline", "pass_tests", t_tests, file_count);
    cbm_log_info("pass.timing", "pass", "tests", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (rc == 0 && !check_cancel(p)) {
        CBM_PROF_START(t_gh);
        rc = run_githistory(p, ctx);
        CBM_PROF_END("pipeline", "pass_githistory", t_gh);
    }
    if (check_cancel(p)) {
        return CBM_NOT_FOUND;
    }
    return rc;
}

/* Run tests, git history, predump passes, and dump+persist. */
static int run_post_extraction(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                               const cbm_file_info_t *files, int file_count,
                               cbm_file_snapshot_t *snapshots) {
    int rc = run_tests_and_history(p, ctx, files, file_count);
    if (rc != 0) {
        return rc;
    }

    CBM_PROF_START(t_predump);
    run_predump_passes(p, ctx);
    CBM_PROF_END("pipeline", "3_predump_passes_total", t_predump);

    if (!check_cancel(p)) {
        struct timespec t;
        CBM_PROF_START(t_dump);
        rc = dump_and_persist_hashes(p, files, file_count, snapshots, &t);
        CBM_PROF_END("pipeline", "4_dump_and_persist", t_dump);
    }
    return rc;
}

#define MIN_FILES_FOR_PARALLEL 50

/* Run structure + extraction passes (parallel or sequential). */
static int run_extraction_phase(cbm_pipeline_t *p, cbm_pipeline_ctx_t *ctx,
                                const cbm_file_info_t *files, int file_count) {
    struct timespec t;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t);
    CBM_PROF_START(t_struct);
    int rc = pass_structure(p, files, file_count);
    CBM_PROF_END_N("pipeline", "pass_structure", t_struct, file_count);
    cbm_log_info("pass.timing", "pass", "structure", "elapsed_ms", itoa_buf((int)elapsed_ms(t)));
    if (rc != 0 || check_cancel(p)) {
        return CBM_NOT_FOUND;
    }

    int worker_count = effective_worker_count(true);
    CBM_PROF_START(t_extract_total);
    rc = (worker_count > SKIP_ONE && file_count > MIN_FILES_FOR_PARALLEL)
             ? run_parallel_pipeline(p, ctx, files, file_count, worker_count, &t)
             : run_sequential_pipeline(p, ctx, files, file_count, &t);
    CBM_PROF_END_N("pipeline", "2_extraction_total", t_extract_total, file_count);
    if (check_cancel(p)) {
        return CBM_NOT_FOUND;
    }
    return rc;
}

static int cbm_pipeline_run_staged(cbm_pipeline_t *p, bool *was_incremental) {
    if (!p) {
        return CBM_NOT_FOUND;
    }
    *was_incremental = false;
    clear_publish_snapshot(p);
    atomic_store_explicit(&p->parser_read_failed, 0, memory_order_relaxed);

    CBM_PROF_START(t_pipeline_total);
    struct timespec t0;
    cbm_clock_gettime(CLOCK_MONOTONIC, &t0);
    cbm_path_alias_collection_t *path_aliases = NULL;
    cbm_file_snapshot_t *source_snapshots = NULL;
    cbm_file_info_t *files = NULL;
    int file_count = 0;
    int rc = 0;

    if (refresh_git_context(p) != 0) {
        cbm_log_warn("pipeline.git_context", "status", "refresh_failed");
        if (p->git_tracked_only) {
            rc = CBM_PIPELINE_ABORT_PRESERVE_DB;
            goto cleanup;
        }
    }
    if (p->git_tracked_only && !pipeline_recipe_unchanged(p)) {
        cbm_log_error("pipeline.err", "phase", "recipe_snapshot");
        rc = CBM_PIPELINE_ABORT_PRESERVE_DB;
        goto cleanup;
    }

    /* C/C++ #define Macro nodes (#375) dominate extraction on macro-dense repos
     * (≈49% of nodes on the Linux kernel), so gate them to full mode — moderate
     * and fast skip them entirely. Set before any extraction dispatch. */
    cbm_set_macro_extraction(p->mode == CBM_MODE_FULL);

    /* Load user-defined extension overrides (fail-open: NULL on error) */
    CBM_PROF_START(t_userconfig);
    /* Trust mode must be a function of Git-tracked inputs only. Global and
     * project user extension config is intentionally ignored because it is
     * loaded before language discovery and is not part of the graph corpus. */
    p->userconfig = p->git_tracked_only ? NULL : cbm_userconfig_load(p->repo_path);
    cbm_set_user_lang_config(p->userconfig);
    CBM_PROF_END("pipeline", "0_userconfig_load", t_userconfig);

    /* Phase 1: discover files. Trust mode iterates only Git's bounded,
     * NUL-framed manifest and never walks untracked directories. */
    CBM_PROF_START(t_discover);
    cbm_discover_opts_t opts = {
        .mode = p->mode,
        .ignore_file = NULL,
        .max_file_size = 0,
        .trusted_git_only = p->git_tracked_only,
    };
    /* Capture skipped subtrees on the pipeline so the MCP layer can report
     * which directories were excluded (#411), plus the individually-ignored
     * files (#963 "purposely not indexed"). Replace any prior lists (e.g. a
     * re-run on the same pipeline) to avoid leaking the previous ones. */
    cbm_discover_free_excluded(p->excluded_dirs, p->excluded_count);
    p->excluded_dirs = NULL;
    p->excluded_count = 0;
    cbm_discover_free_ignored(p->ignored_files, p->ignored_count);
    p->ignored_files = NULL;
    p->ignored_count = 0;
    p->ignored_total = 0;
    rc = p->git_tracked_only
             ? discover_tracked_files(p, &files, &file_count)
             : cbm_discover_ex2(p->repo_path, &opts, &files, &file_count, &p->excluded_dirs,
                                &p->excluded_count, &p->ignored_files, &p->ignored_count,
                                &p->ignored_total);
    if (rc != 0) {
        cbm_log_error("pipeline.err", "phase", "discover", "rc", itoa_buf(rc));
    }
    CBM_PROF_END_N("pipeline", "1_discover", t_discover, file_count);
    cbm_log_info("pipeline.discover", "files", itoa_buf(file_count), "elapsed_ms",
                 itoa_buf((int)elapsed_ms(t0)));
    if (rc != 0 || check_cancel(p)) {
        rc = CBM_NOT_FOUND;
        goto cleanup;
    }
    if (p->git_tracked_only &&
        cbm_pipeline_capture_file_snapshots(p, files, file_count, &source_snapshots) != 0) {
        rc = CBM_PIPELINE_ABORT_PRESERVE_DB;
        goto cleanup;
    }
    if (p->git_tracked_only &&
        finalize_trusted_source_classification(p, files, source_snapshots, &file_count) != 0) {
        rc = CBM_PIPELINE_ABORT_PRESERVE_DB;
        goto cleanup;
    }
    if (p->git_tracked_only && !seal_trusted_snapshot_dir(p)) {
        rc = CBM_PIPELINE_ABORT_PRESERVE_DB;
        goto cleanup;
    }

    /* Check for existing DB → try incremental or delete for reindex */
    rc = try_incremental_or_delete_db(p, files, file_count, source_snapshots);
    if (rc == CBM_PIPELINE_ABORT_PRESERVE_DB) {
        goto cleanup;
    }
    if (rc >= 0) {
        *was_incremental = !p->git_tracked_only;
        goto cleanup;
    }
    cbm_log_info("pipeline.route", "path", "full");

    /* Phase 2: Create graph buffer and registry */
    p->gbuf = cbm_gbuf_new(p->project_name, p->repo_path);
    p->registry = cbm_registry_new();

    /* Phase 2b: Load build-tool path aliases (tsconfig/jsconfig today). NULL
     * when no usable configs are found — non-TS projects pay nothing. */
    path_aliases =
        cbm_load_path_aliases_trusted(p->repo_path, p->excluded_dirs, p->excluded_count, p);

    /* Build shared context for pass functions */
    cbm_pipeline_ctx_t ctx = {
        .project_name = p->project_name,
        .repo_path = p->repo_path,
        .gbuf = p->gbuf,
        .registry = p->registry,
        .cancelled = p->cancelled,
        .pipeline = p, /* so passes can record per-file skips (Track B) */
        .mode = (int)p->mode,
        .path_aliases = path_aliases,
        .excluded_dirs = p->excluded_dirs,
        .excluded_count = p->excluded_count,
    };

    rc = run_extraction_phase(p, &ctx, files, file_count);
    if (p->git_tracked_only && atomic_load_explicit(&p->parser_read_failed, memory_order_relaxed)) {
        rc = CBM_PIPELINE_ABORT_PRESERVE_DB;
    }
    if (rc != 0) {
        goto cleanup;
    }

    rc = run_post_extraction(p, &ctx, files, file_count, source_snapshots);
    if (rc != 0) {
        goto cleanup;
    }

    cbm_log_info("pipeline.done", "nodes", itoa_buf(p->committed_nodes), "edges",
                 itoa_buf(p->committed_edges), "elapsed_ms", itoa_buf((int)elapsed_ms(t0)));
    CBM_PROF_END("pipeline", "TOTAL", t_pipeline_total);

cleanup:
    if (p->git_tracked_only && rc == 0) {
        p->publish_files = files;
        p->publish_snapshots = source_snapshots;
        p->publish_file_count = file_count;
        files = NULL;
        source_snapshots = NULL;
        file_count = 0;
    }
    free(source_snapshots);
    cbm_pkgmap_free(cbm_pipeline_get_pkgmap());
    cbm_pipeline_set_pkgmap(NULL);
    cbm_discover_free(files, file_count);
    cbm_gbuf_free(p->gbuf);
    p->gbuf = NULL;
    cbm_registry_free(p->registry);
    p->registry = NULL;
    cbm_path_alias_collection_free(path_aliases);
    /* Clear and free user extension config */
    cbm_set_user_lang_config(NULL);
    cbm_userconfig_free(p->userconfig);
    p->userconfig = NULL;
    return rc;
}

static void cleanup_staging_db(const char *path) {
    if (!path) {
        return;
    }
    (void)cbm_unlink(path);
    (void)cbm_remove_db_sidecars(path);
}

static bool ensure_db_parent(const char *path) {
    if (!path) {
        return false;
    }
    char *dir = strdup(path);
    if (!dir) {
        return false;
    }
    char *slash = strrchr(dir, '/');
#ifdef _WIN32
    char *backslash = strrchr(dir, '\\');
    if (backslash && (!slash || backslash > slash)) {
        slash = backslash;
    }
#endif
    if (!slash) {
        free(dir);
        return true;
    }
    *slash = '\0';
    bool ok = dir[0] == '\0' || cbm_mkdir_p(dir, CBM_DIR_PERMS);
    free(dir);
    return ok;
}

static char *create_staging_path(const char *final_path) {
    if (!final_path) {
        return NULL;
    }
    static const char suffix[] = ".stage.XXXXXX";
    size_t final_len = strlen(final_path);
    if (final_len > SIZE_MAX - sizeof(suffix)) {
        return NULL;
    }
    size_t path_size = final_len + sizeof(suffix);
#ifdef _WIN32
    /* The Windows cbm_mkstemp compatibility contract may expand a /tmp/
     * prefix in-place and copies through a 4 KiB scratch path. Give it that
     * full capacity, and reject longer inputs exactly rather than truncating. */
    if (path_size > CBM_SZ_4K) {
        return NULL;
    }
    path_size = CBM_SZ_4K;
#endif
    char *path = (char *)malloc(path_size);
    if (!path) {
        return NULL;
    }
    memcpy(path, final_path, final_len);
    memcpy(path + final_len, suffix, sizeof(suffix));
    int fd = cbm_mkstemp(path);
    if (fd < 0) {
        free(path);
        return NULL;
    }
#ifdef _WIN32
    _close(fd);
#else
    close(fd);
#endif
    return path;
}

/* A backup-failed destination may still have the only recoverable WAL or
 * rollback journal. Publication may replace its main file only when no
 * sidecar exists; otherwise fail without mutating the old generation. */
static bool db_sidecars_absent(const char *db_path) {
    if (!db_path || !db_path[0]) {
        return false;
    }
    enum { SIDECAR_PATH_MAX = 4096 };
    char side[SIDECAR_PATH_MAX];
    if (strlen(db_path) > sizeof(side) - sizeof("-journal")) {
        return false;
    }
    static const char *const suffixes[] = {"-wal", "-shm", "-journal"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(side, sizeof(side), "%s%s", db_path, suffixes[i]);
        if (n <= 0 || (size_t)n >= sizeof(side)) {
            return false;
        }
        struct stat side_st;
        if (stat(side, &side_st) == 0 || errno != ENOENT) {
            return false;
        }
    }
    return true;
}

static bool prepare_publish_destination(const char *final_path, bool final_existed,
                                        bool backup_succeeded) {
    struct stat current_st;
    bool final_exists_now = stat(final_path, &current_st) == 0;
    if (final_exists_now != final_existed) {
        return false;
    }
    if (!final_exists_now) {
        /* A crashed generation can leave sidecars without a main file. */
        return cbm_remove_db_sidecars(final_path) == 0;
    }
    if (!backup_succeeded) {
        bool safe_to_replace = db_sidecars_absent(final_path);
        if (!safe_to_replace) {
            cbm_log_error("pipeline.err", "phase", "publish", "reason",
                          "backup_failed_sidecars_preserved", "path", final_path);
        }
        return safe_to_replace;
    }
    return cbm_store_prepare_path_for_replace(final_path) == CBM_STORE_OK &&
           cbm_remove_db_sidecars(final_path) == 0;
}

static int seal_staging_db(const char *staging_path) {
    cbm_store_t *store = cbm_store_open_path(staging_path);
    if (!store) {
        return CBM_NOT_FOUND;
    }
    int rc =
        cbm_store_check_integrity(store) && cbm_store_prepare_for_publish(store) == CBM_STORE_OK
            ? 0
            : CBM_NOT_FOUND;
    cbm_store_close(store);
    if (rc == 0 && cbm_remove_db_sidecars(staging_path) != 0) {
        rc = CBM_NOT_FOUND;
    }
    return rc;
}

static int export_after_publish(cbm_pipeline_t *p, const char *final_path, bool was_incremental) {
    if (p->persistence) {
        CBM_PROF_START(t_art);
        int rc = cbm_artifact_export(final_path, p->repo_path, p->project_name, CBM_ARTIFACT_BEST);
        CBM_PROF_END("persist", "6_artifact_export", t_art);
        if (rc != 0) {
            const char *err = cbm_artifact_export_last_error();
            cbm_log_error("pipeline.err", "phase", "artifact_export", "err", err ? err : "unknown");
        }
        return rc;
    }
    if (was_incremental && p->repo_path && cbm_artifact_exists(p->repo_path)) {
        (void)cbm_artifact_export(final_path, p->repo_path, p->project_name, CBM_ARTIFACT_FAST);
    }
    return 0;
}

static int verify_publish_snapshot(cbm_pipeline_t *p) {
    if (!p || !p->git_tracked_only) {
        return 0;
    }
    if (atomic_load_explicit(&p->parser_read_failed, memory_order_relaxed) ||
        !pipeline_recipe_unchanged(p) || cbm_pipeline_verify_git_snapshot(p) != 0 ||
        verify_captured_parser_snapshots(p, p->publish_files, p->publish_file_count,
                                         p->publish_snapshots) != 0 ||
        verify_captured_parser_snapshots(p, p->auxiliary_files, p->auxiliary_file_count,
                                         p->auxiliary_snapshots) != 0 ||
        cbm_pipeline_verify_file_snapshots(p, p->publish_files, p->publish_file_count,
                                           p->publish_snapshots) != 0 ||
        cbm_pipeline_verify_file_snapshots(p, p->auxiliary_files, p->auxiliary_file_count,
                                           p->auxiliary_snapshots) != 0) {
        cbm_log_error("pipeline.err", "phase", "publish_snapshot_verify");
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }
    return 0;
}

int cbm_pipeline_run(cbm_pipeline_t *p) {
    if (!p) {
        return CBM_NOT_FOUND;
    }
    char *final_path = resolve_db_path(p);
    if (!final_path || !ensure_db_parent(final_path)) {
        free(final_path);
        return CBM_NOT_FOUND;
    }
    struct stat final_st;
    bool final_existed = stat(final_path, &final_st) == 0;
    if (p->git_tracked_only && final_existed) {
        cbm_store_t *published = cbm_store_open_path_query_strict(final_path);
        bool unchanged = published && cbm_pipeline_trusted_snapshot_matches_store(
                                          p->repo_path, p->project_name, published);
        int committed_nodes = -1;
        int committed_edges = -1;
        if (unchanged) {
            committed_nodes = cbm_store_count_nodes(published, p->project_name);
            committed_edges = cbm_store_count_edges(published, p->project_name);
            if (p->before_trusted_noop_hook) {
                p->before_trusted_noop_hook(p, final_path, p->before_trusted_noop_hook_ctx);
            }
            unchanged = committed_nodes >= 0 && committed_edges >= 0 &&
                        cbm_store_strict_snapshot_valid(published);
        }
        if (unchanged) {
            p->committed_nodes = committed_nodes;
            p->committed_edges = committed_edges;
        }
        cbm_store_close(published);
        if (unchanged) {
            cbm_log_info("pipeline.route", "path", "trusted_snapshot_noop");
            free(final_path);
            return 0;
        }
    }
    char *staging_path = create_staging_path(final_path);
    if (!staging_path) {
        free(final_path);
        return CBM_NOT_FOUND;
    }

    bool backup_succeeded = false;
    if (final_existed) {
        backup_succeeded = cbm_store_backup_path(final_path, staging_path) == CBM_STORE_OK;
        if (!backup_succeeded) {
            cbm_log_warn("pipeline.stage", "action", "backup_failed_full_rebuild", "path",
                         final_path);
            cleanup_staging_db(staging_path);
        }
    }

    char *configured_db_path = p->db_path;
    p->db_path = strdup(staging_path);
    if (!p->db_path) {
        p->db_path = configured_db_path;
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_NOT_FOUND;
    }
    bool was_incremental = false;
    int rc = cbm_pipeline_run_staged(p, &was_incremental);
    free(p->db_path);
    p->db_path = configured_db_path;

    if (rc != 0 || check_cancel(p) || seal_staging_db(staging_path) != 0) {
        int failure_rc = rc != 0 ? rc : CBM_NOT_FOUND;
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return failure_rc;
    }

    if (p->before_publish_hook) {
        p->before_publish_hook(p, staging_path, p->before_publish_hook_ctx);
    }
    if (check_cancel(p)) {
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_NOT_FOUND;
    }
    /* A test hook may inspect the DB through SQLite and re-enable WAL mode;
     * seal once more before installing the standalone main file. */
    if (seal_staging_db(staging_path) != 0) {
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_NOT_FOUND;
    }
    if (p->git_tracked_only && atomic_load_explicit(&p->parser_read_failed, memory_order_relaxed)) {
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_PIPELINE_ABORT_PRESERVE_DB;
    }
    if (!prepare_publish_destination(final_path, final_existed, backup_succeeded)) {
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_NOT_FOUND;
    }
    /* Test-only seam runs before the last seal/verification; product code owns
     * the rename so a hook cannot mutate a source and publish it in one opaque
     * callback. */
    if (p->rename_hook && p->rename_hook(staging_path, final_path, p->rename_hook_ctx) != 0) {
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_NOT_FOUND;
    }
    if (check_cancel(p) || seal_staging_db(staging_path) != 0 || verify_publish_snapshot(p) != 0) {
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_NOT_FOUND;
    }
    if (cbm_rename_replace(staging_path, final_path) != 0) {
        cbm_log_error("pipeline.err", "phase", "publish", "path", final_path);
        clear_publish_snapshot(p);
        cleanup_staging_db(staging_path);
        free(staging_path);
        free(final_path);
        return CBM_NOT_FOUND;
    }

    rc = export_after_publish(p, final_path, was_incremental);
    clear_publish_snapshot(p);
    free(staging_path);
    free(final_path);
    return rc;
}
