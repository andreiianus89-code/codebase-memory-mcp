/*
 * artifact.c — Persistent artifact export/import for team sharing.
 *
 * Export: strip indexes → VACUUM INTO temp → zstd compress → write .zst + metadata
 * Import: decompress → write to cache → open (auto-creates indexes) → integrity check
 */
#include "foundation/constants.h"

enum {
    ART_DIR_PERMS = 0755,
    ART_ZSTD_FAST = 3,
    ART_ZSTD_BEST = 9,
    ART_RATIO_SCALE = 10, /* multiply ratio by 10 for integer logging */
    ART_NUL = 1,          /* NUL terminator byte */
};
#define ART_BYTES_PER_MB ((size_t)1024 * 1024)

/* Generous ceiling on an imported artifact's decompressed size. Real indexes
 * (a full Linux-kernel DB is ~14 GB) fit comfortably; a frame that declares
 * more than this is rejected before any allocation so a crafted content size
 * can neither trigger a runaway allocation nor be used to desync the decoder
 * capacity from the destination buffer. */
#define ART_MAX_DECOMPRESSED_BYTES ((size_t)64 * 1024 * ART_BYTES_PER_MB)

#include "pipeline/artifact.h"
#include "pipeline/artifact_internal.h"
#include "store/store.h"
#include "foundation/platform.h"
#include "foundation/compat_fs.h"
#include "foundation/compat.h"
#include "foundation/log.h"
#include "foundation/sha256.h"
#include "foundation/str_util.h" /* cbm_validate_shell_arg — git shell-out hardening */
#include "foundation/trusted_fs.h"
#include "foundation/trusted_fs_internal.h"

#include "zstd_store.h"

#include <sqlite3.h>
#include <yyjson/yyjson.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef _WIN32
#include "foundation/win_utf8.h"
#include <io.h>
#include <windows.h>
#else
#include <sys/file.h>
#endif

/* ── Helpers ──────────────────────────────────────────────────────── */

/* Thread-local rotating buffers for small int→string conversions (logging).
 * Rotating allows multiple itoa_buf() calls in a single log statement. */
enum { ART_RING = 4, ART_RING_MASK = 3 };
static _Thread_local char g_export_error[CBM_SZ_512];
static cbm_artifact_snapshot_path_hook_fn g_snapshot_path_hook;
static void *g_snapshot_path_hook_context;
static cbm_artifact_payload_published_hook_fn g_payload_published_hook;
static void *g_payload_published_hook_context;
static atomic_uint_fast64_t g_artifact_temp_sequence;

void cbm_artifact_set_snapshot_path_hook_for_test(cbm_artifact_snapshot_path_hook_fn hook,
                                                  void *context) {
    g_snapshot_path_hook = hook;
    g_snapshot_path_hook_context = context;
}

void cbm_artifact_set_payload_published_hook_for_test(cbm_artifact_payload_published_hook_fn hook,
                                                      void *context) {
    g_payload_published_hook = hook;
    g_payload_published_hook_context = context;
}

static const char *itoa_buf(int v) {
    static _Thread_local char bufs[ART_RING][CBM_SZ_32];
    static _Thread_local int idx = 0;
    int i = idx;
    idx = (idx + ART_NUL) & ART_RING_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", v);
    return bufs[i];
}

const char *cbm_artifact_export_last_error(void) {
    return g_export_error[0] ? g_export_error : NULL;
}

static void clear_export_error(void) {
    g_export_error[0] = '\0';
}

static int artifact_export_fail(const char *stage, const char *path, const char *err, int err_no) {
    const char *safe_stage = stage ? stage : "unknown";
    const char *safe_err = err ? err : "unknown";

    if (path && err_no != 0) {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s errno=%d path=%s", safe_stage,
                 safe_err, err_no, path);
    } else if (path) {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s path=%s", safe_stage, safe_err,
                 path);
    } else if (err_no != 0) {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s errno=%d", safe_stage, safe_err,
                 err_no);
    } else {
        snprintf(g_export_error, sizeof(g_export_error), "%s: %s", safe_stage, safe_err);
    }

    if (path && err_no != 0) {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err, "errno",
                      itoa_buf(err_no), "path", path);
    } else if (path) {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err, "path", path);
    } else if (err_no != 0) {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err, "errno",
                      itoa_buf(err_no));
    } else {
        cbm_log_error("artifact.export", "stage", safe_stage, "err", safe_err);
    }
    return CBM_NOT_FOUND;
}

typedef struct {
    const char *err;
    int err_no;
} artifact_file_error_t;

typedef struct {
    char repo_path[CBM_SZ_4K];
    char path[CBM_SZ_4K];
    cbm_trusted_root_t *repo_root;
#ifdef _WIN32
    cbm_trusted_root_t *root;
    HANDLE lock_handle;
    OVERLAPPED lock_range;
#else
    int fd;
    dev_t device;
    ino_t inode;
#endif
    bool locked;
} artifact_directory_t;

static void file_error_clear(artifact_file_error_t *out) {
    if (out) {
        out->err = NULL;
        out->err_no = 0;
    }
}

static void file_error_set(artifact_file_error_t *out, const char *err, int err_no) {
    if (out) {
        out->err = err;
        out->err_no = err_no;
    }
}

static bool artifact_base_name_valid(const char *name) {
    return name && name[0] && strcmp(name, ".") != 0 && strcmp(name, "..") != 0 &&
           strchr(name, '/') == NULL && strchr(name, '\\') == NULL;
}

static bool artifact_directory_revalidate(const artifact_directory_t *directory) {
    if (!directory || !directory->repo_root ||
        !cbm_trusted_root_matches_path(directory->repo_root, directory->repo_path)) {
        return false;
    }
#ifdef _WIN32
    return directory->root && cbm_trusted_root_matches_path(directory->root, directory->path);
#else
    struct stat pinned;
    struct stat named;
    int flags = O_RDONLY | O_DIRECTORY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int probe = open(directory->path, flags);
    bool valid = directory->fd >= 0 && probe >= 0 && fstat(directory->fd, &pinned) == 0 &&
                 fstat(probe, &named) == 0 && S_ISDIR(pinned.st_mode) && S_ISDIR(named.st_mode) &&
                 pinned.st_dev == directory->device && pinned.st_ino == directory->inode &&
                 named.st_dev == directory->device && named.st_ino == directory->inode;
    if (probe >= 0) {
        (void)close(probe);
    }
    return valid;
#endif
}

#ifdef _WIN32
static wchar_t *artifact_win_child_path(const artifact_directory_t *directory,
                                        const char *base_name) {
    if (!directory || !artifact_base_name_valid(base_name)) {
        return NULL;
    }
    char path[CBM_SZ_4K];
    int written = snprintf(path, sizeof(path), "%s/%s", directory->path, base_name);
    return written > 0 && (size_t)written < sizeof(path) ? cbm_path_to_wide(path) : NULL;
}

static bool artifact_win_regular_handle(HANDLE handle, BY_HANDLE_FILE_INFORMATION *out) {
    BY_HANDLE_FILE_INFORMATION information;
    bool valid = handle != INVALID_HANDLE_VALUE && GetFileType(handle) == FILE_TYPE_DISK &&
                 GetFileInformationByHandle(handle, &information) != 0 &&
                 (information.dwFileAttributes &
                  (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
                 information.nNumberOfLinks == 1 &&
                 SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) != 0;
    if (valid && out) {
        *out = information;
    }
    return valid;
}

static bool artifact_win_same_file(const BY_HANDLE_FILE_INFORMATION *left,
                                   const BY_HANDLE_FILE_INFORMATION *right) {
    return left && right && left->dwVolumeSerialNumber == right->dwVolumeSerialNumber &&
           left->nFileIndexHigh == right->nFileIndexHigh &&
           left->nFileIndexLow == right->nFileIndexLow;
}

static bool artifact_win_child_revalidate(const artifact_directory_t *directory,
                                          const char *base_name, HANDLE handle,
                                          const BY_HANDLE_FILE_INFORMATION *expected) {
    if (!artifact_directory_revalidate(directory)) {
        return false;
    }
    BY_HANDLE_FILE_INFORMATION actual;
    if (!artifact_win_regular_handle(handle, &actual) ||
        (expected && !artifact_win_same_file(expected, &actual))) {
        return false;
    }
    wchar_t *path = artifact_win_child_path(directory, base_name);
    HANDLE probe = path ? CreateFileW(path, FILE_READ_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                      OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
                        : INVALID_HANDLE_VALUE;
    free(path);
    BY_HANDLE_FILE_INFORMATION named;
    bool valid =
        artifact_win_regular_handle(probe, &named) && artifact_win_same_file(&actual, &named);
    if (probe != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(probe);
    }
    return valid;
}
#endif

static void artifact_directory_close(artifact_directory_t *directory) {
    if (!directory) {
        return;
    }
#ifdef _WIN32
    if (directory->locked && directory->lock_handle != INVALID_HANDLE_VALUE) {
        (void)UnlockFileEx(directory->lock_handle, 0, 1, 0, &directory->lock_range);
    }
    if (directory->lock_handle != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(directory->lock_handle);
    }
    cbm_trusted_root_close(directory->root);
#else
    if (directory->locked && directory->fd >= 0) {
        int result;
        do {
            result = flock(directory->fd, LOCK_UN);
        } while (result != 0 && errno == EINTR);
    }
    if (directory->fd >= 0) {
        (void)close(directory->fd);
    }
#endif
    cbm_trusted_root_close(directory->repo_root);
    memset(directory, 0, sizeof(*directory));
#ifdef _WIN32
    directory->lock_handle = INVALID_HANDLE_VALUE;
#else
    directory->fd = -1;
#endif
}

static bool artifact_directory_open(const char *repo_path, bool create,
                                    artifact_directory_t *directory) {
    if (!repo_path || !directory) {
        return false;
    }
    memset(directory, 0, sizeof(*directory));
#ifdef _WIN32
    directory->lock_handle = INVALID_HANDLE_VALUE;
#else
    directory->fd = -1;
#endif
    int repo_written =
        snprintf(directory->repo_path, sizeof(directory->repo_path), "%s", repo_path);
    int path_written =
        snprintf(directory->path, sizeof(directory->path), "%s/%s", repo_path, CBM_ARTIFACT_DIR);
    if (repo_written <= 0 || (size_t)repo_written >= sizeof(directory->repo_path) ||
        path_written <= 0 || (size_t)path_written >= sizeof(directory->path) ||
        cbm_trusted_root_open_mutable_ancestors(repo_path, &directory->repo_root) != 0) {
        artifact_directory_close(directory);
        return false;
    }

#ifdef _WIN32
    if (create) {
        wchar_t *wide = cbm_path_to_wide(directory->path);
        BOOL made = wide ? CreateDirectoryW(wide, NULL) : FALSE;
        DWORD error = made ? ERROR_SUCCESS : GetLastError();
        free(wide);
        if (!made && error != ERROR_ALREADY_EXISTS) {
            artifact_directory_close(directory);
            return false;
        }
    }
    int root_rc = cbm_trusted_root_open_mutable_ancestors(directory->path, &directory->root);
    if (root_rc != 0 || !artifact_directory_revalidate(directory)) {
        artifact_directory_close(directory);
        return false;
    }
#else
    int repo_fd = cbm_trusted_root_dup_native_fd(directory->repo_root);
    if (repo_fd < 0) {
        artifact_directory_close(directory);
        return false;
    }
    if (create && mkdirat(repo_fd, CBM_ARTIFACT_DIR, ART_DIR_PERMS) != 0 && errno != EEXIST) {
        (void)close(repo_fd);
        artifact_directory_close(directory);
        return false;
    }
    int flags = O_RDONLY | O_DIRECTORY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    directory->fd = openat(repo_fd, CBM_ARTIFACT_DIR, flags);
    struct stat by_handle;
    struct stat by_name;
    bool valid = directory->fd >= 0 && fstat(directory->fd, &by_handle) == 0 &&
                 fstatat(repo_fd, CBM_ARTIFACT_DIR, &by_name, AT_SYMLINK_NOFOLLOW) == 0 &&
                 S_ISDIR(by_handle.st_mode) && S_ISDIR(by_name.st_mode) &&
                 by_handle.st_dev == by_name.st_dev && by_handle.st_ino == by_name.st_ino;
    (void)close(repo_fd);
    if (!valid) {
        artifact_directory_close(directory);
        return false;
    }
    directory->device = by_handle.st_dev;
    directory->inode = by_handle.st_ino;
    if (!artifact_directory_revalidate(directory)) {
        artifact_directory_close(directory);
        return false;
    }
#endif
    return true;
}

static bool artifact_write_all_native(
#ifdef _WIN32
    HANDLE file,
#else
    int file,
#endif
    const char *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
#ifdef _WIN32
        DWORD chunk = length - offset > MAXDWORD ? MAXDWORD : (DWORD)(length - offset);
        DWORD written = 0;
        if (!WriteFile(file, data + offset, chunk, &written, NULL) || written == 0) {
            return false;
        }
        offset += (size_t)written;
#else
        ssize_t written = write(file, data + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += (size_t)written;
#endif
    }
    return true;
}

static void artifact_unlink_child(artifact_directory_t *directory, const char *base_name);

static bool artifact_create_gitattributes(artifact_directory_t *directory) {
    static const char contents[] =
        "# Auto-generated by codebase-memory-mcp\n"
        "# Prevent merge conflicts on compressed artifact\n" CBM_ARTIFACT_FILENAME
        " binary merge=ours\n";
    if (!artifact_directory_revalidate(directory)) {
        return false;
    }
#ifdef _WIN32
    wchar_t *path = artifact_win_child_path(directory, ".gitattributes");
    HANDLE file = path ? CreateFileW(path, GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW,
                                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
                       : INVALID_HANDLE_VALUE;
    DWORD error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    free(path);
    if (file == INVALID_HANDLE_VALUE) {
        return error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS;
    }
    BY_HANDLE_FILE_INFORMATION identity;
    bool ok = artifact_win_regular_handle(file, &identity) &&
              artifact_win_child_revalidate(directory, ".gitattributes", file, &identity) &&
              artifact_write_all_native(file, contents, sizeof(contents) - 1U) &&
              FlushFileBuffers(file) != 0;
    bool closed = CloseHandle(file) != 0;
    if (!ok) {
        artifact_unlink_child(directory, ".gitattributes");
    }
    return ok && closed;
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int file = openat(directory->fd, ".gitattributes", flags, 0644);
    if (file < 0) {
        if (errno != EEXIST) {
            return false;
        }
        int existing_flags = O_RDONLY;
#ifdef O_CLOEXEC
        existing_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        existing_flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
        existing_flags |= O_NONBLOCK;
#endif
        int existing = openat(directory->fd, ".gitattributes", existing_flags);
        struct stat by_handle;
        struct stat by_name;
        bool safe = existing >= 0 && fstat(existing, &by_handle) == 0 &&
                    S_ISREG(by_handle.st_mode) && by_handle.st_nlink == 1 &&
                    fstatat(directory->fd, ".gitattributes", &by_name, AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISREG(by_name.st_mode) && by_name.st_dev == by_handle.st_dev &&
                    by_name.st_ino == by_handle.st_ino;
        if (existing >= 0) {
            safe = close(existing) == 0 && safe;
        }
        return safe;
    }
    struct stat by_handle;
    struct stat by_name;
    bool same = fstat(file, &by_handle) == 0 && S_ISREG(by_handle.st_mode) &&
                by_handle.st_nlink == 1 &&
                fstatat(directory->fd, ".gitattributes", &by_name, AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISREG(by_name.st_mode) && by_name.st_dev == by_handle.st_dev &&
                by_name.st_ino == by_handle.st_ino;
    bool ok = same && artifact_write_all_native(file, contents, sizeof(contents) - 1U) &&
              fsync(file) == 0;
    if (!ok && same) {
        (void)unlinkat(directory->fd, ".gitattributes", 0);
    }
    bool closed = close(file) == 0;
    return ok && closed;
#endif
}

static bool artifact_lock_acquire(artifact_directory_t *directory, bool exclusive) {
    if (!directory || directory->locked || !artifact_directory_revalidate(directory)) {
        return false;
    }
#ifdef _WIN32
    wchar_t *path = artifact_win_child_path(directory, ".gitattributes");
    directory->lock_handle =
        path ? CreateFileW(path, GENERIC_READ | FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
             : INVALID_HANDLE_VALUE;
    free(path);
    BY_HANDLE_FILE_INFORMATION identity;
    if (!artifact_win_regular_handle(directory->lock_handle, &identity) ||
        !artifact_win_child_revalidate(directory, ".gitattributes", directory->lock_handle,
                                       &identity)) {
        artifact_directory_close(directory);
        return false;
    }
    /* Pin the validated lock child before dropping the strict artifact root.
     * Waiting with the root open would block the current owner from renaming
     * bundle children; the no-delete child handle keeps the root non-empty. */
    cbm_trusted_root_close(directory->root);
    directory->root = NULL;
    memset(&directory->lock_range, 0, sizeof(directory->lock_range));
    DWORD flags = exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0;
    if (!LockFileEx(directory->lock_handle, flags, 0, 1, 0, &directory->lock_range)) {
        artifact_directory_close(directory);
        return false;
    }
    directory->locked = true;
    if (cbm_trusted_root_open_mutable_ancestors(directory->path, &directory->root) != 0 ||
        !artifact_win_child_revalidate(directory, ".gitattributes", directory->lock_handle,
                                       &identity) ||
        (exclusive &&
         cbm_trusted_root_upgrade_mutable_children(directory->root, directory->path) != 0)) {
        artifact_directory_close(directory);
        return false;
    }
#else
    int result = -1;
    do {
        /* The pinned directory inode is the stable POSIX coordination object;
         * `.gitattributes` is Git metadata, not part of bundle admission. */
        result = flock(directory->fd, exclusive ? LOCK_EX : LOCK_SH);
    } while (result != 0 && errno == EINTR);
    bool safe = result == 0 && artifact_directory_revalidate(directory);
    if (!safe) {
        artifact_directory_close(directory);
        return false;
    }
    directory->locked = true;
#endif
    return true;
}

static char *artifact_read_file_alloc(const artifact_directory_t *directory, const char *base_name,
                                      size_t max_bytes, size_t *out_len) {
    if (!directory || !artifact_base_name_valid(base_name) || !out_len ||
        !artifact_directory_revalidate(directory)) {
        return NULL;
    }
#ifdef _WIN32
    unsigned char *data = NULL;
    size_t length = 0;
    if (!directory->root || cbm_trusted_root_read_file(directory->root, base_name, max_bytes, &data,
                                                       &length, NULL) != 0) {
        return NULL;
    }
    *out_len = length;
    return (char *)data;
#else
    /* Compare sub-second timestamps as well as identity/size; a same-sized
     * replacement inside one wall-clock second must not pass as a stable read. */
#ifdef __APPLE__
#define ARTIFACT_MTIME_NS(value) ((value).st_mtimespec.tv_nsec)
#define ARTIFACT_CTIME_NS(value) ((value).st_ctimespec.tv_nsec)
#else
#define ARTIFACT_MTIME_NS(value) ((value).st_mtim.tv_nsec)
#define ARTIFACT_CTIME_NS(value) ((value).st_ctim.tv_nsec)
#endif
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif
    int file = openat(directory->fd, base_name, flags);
    struct stat before;
    if (file < 0 || fstat(file, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
        before.st_size <= 0 || (uintmax_t)before.st_size > (uintmax_t)(SIZE_MAX - 1U) ||
        (max_bytes != 0 && (uintmax_t)before.st_size > (uintmax_t)max_bytes)) {
        if (file >= 0) {
            (void)close(file);
        }
        return NULL;
    }
    size_t expected = (size_t)before.st_size;
    char *data = malloc(expected + 1U);
    size_t used = 0;
    bool ok = data != NULL;
    while (ok && used < expected) {
        ssize_t got = read(file, data + used, expected - used);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            ok = false;
            break;
        }
        used += (size_t)got;
    }
    unsigned char extra = 0;
    ssize_t extra_read = -1;
    if (ok) {
        do {
            extra_read = read(file, &extra, 1);
        } while (extra_read < 0 && errno == EINTR);
    }
    struct stat after;
    ok = ok && extra_read == 0 && fstat(file, &after) == 0 && before.st_dev == after.st_dev &&
         before.st_ino == after.st_ino && before.st_size == after.st_size &&
         before.st_mtime == after.st_mtime && before.st_ctime == after.st_ctime &&
         ARTIFACT_MTIME_NS(before) == ARTIFACT_MTIME_NS(after) &&
         ARTIFACT_CTIME_NS(before) == ARTIFACT_CTIME_NS(after);
    (void)close(file);
    if (!ok || used != expected) {
        free(data);
        return NULL;
    }
    data[used] = '\0';
    *out_len = used;
#undef ARTIFACT_MTIME_NS
#undef ARTIFACT_CTIME_NS
    return data;
#endif
}

static bool artifact_unique_temp_name(const char *target, char *out, size_t out_size) {
    uint64_t sequence =
        atomic_fetch_add_explicit(&g_artifact_temp_sequence, 1, memory_order_relaxed) + 1U;
#ifdef _WIN32
    unsigned long process = (unsigned long)GetCurrentProcessId();
#else
    unsigned long process = (unsigned long)getpid();
#endif
    int written =
        snprintf(out, out_size, ".%s.tmp-%lu-%llu", target, process, (unsigned long long)sequence);
    return written > 0 && (size_t)written < out_size;
}

static void artifact_unlink_child(artifact_directory_t *directory, const char *base_name) {
    if (!directory || !artifact_base_name_valid(base_name)) {
        return;
    }
#ifdef _WIN32
    wchar_t *path = artifact_win_child_path(directory, base_name);
    if (path) {
        (void)DeleteFileW(path);
    }
    free(path);
#else
    (void)unlinkat(directory->fd, base_name, 0);
#endif
}

typedef struct {
    char name[CBM_SZ_512];
    bool exists;
} artifact_staged_file_t;

static void artifact_staged_discard(artifact_directory_t *directory,
                                    artifact_staged_file_t *staged) {
    if (staged && staged->exists) {
        artifact_unlink_child(directory, staged->name);
        staged->exists = false;
    }
}

static bool artifact_sync_directory(const artifact_directory_t *directory) {
#ifdef _WIN32
    (void)directory;
    return true; /* MoveFileExW uses MOVEFILE_WRITE_THROUGH below. */
#else
    int result;
    do {
        result = fsync(directory->fd);
    } while (result != 0 && errno == EINTR);
    return result == 0 || errno == EINVAL || errno == ENOTSUP || errno == EROFS;
#endif
}

static int artifact_stage_file(artifact_directory_t *directory, const char *target,
                               const char *data, size_t length, artifact_staged_file_t *staged,
                               artifact_file_error_t *out_err) {
    file_error_clear(out_err);
    if (staged) {
        memset(staged, 0, sizeof(*staged));
    }
    if (!directory || !artifact_base_name_valid(target) || !data || !staged ||
        !artifact_directory_revalidate(directory)) {
        file_error_set(out_err, "unsafe_parent", 0);
        return CBM_NOT_FOUND;
    }
    if (!artifact_unique_temp_name(target, staged->name, sizeof(staged->name))) {
        file_error_set(out_err, "path_too_long", 0);
        return CBM_NOT_FOUND;
    }

#ifdef _WIN32
    wchar_t *temp_path = artifact_win_child_path(directory, staged->name);
    HANDLE file =
        temp_path
            ? CreateFileW(temp_path, GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL,
                          CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL)
            : INVALID_HANDLE_VALUE;
    DWORD open_error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    BY_HANDLE_FILE_INFORMATION identity;
    bool opened = artifact_win_regular_handle(file, &identity) &&
                  artifact_win_child_revalidate(directory, staged->name, file, &identity);
    bool written =
        opened && artifact_write_all_native(file, data, length) && FlushFileBuffers(file) != 0;
    bool closed = file != INVALID_HANDLE_VALUE && CloseHandle(file) != 0;
    free(temp_path);
    if (!opened || !written || !closed) {
        artifact_unlink_child(directory, staged->name);
        file_error_set(out_err, !opened ? "open_temp" : "write_temp", (int)open_error);
        return CBM_NOT_FOUND;
    }
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int file = openat(directory->fd, staged->name, flags, 0644);
    int open_error = errno;
    struct stat by_handle;
    struct stat by_name;
    bool opened = file >= 0 && fstat(file, &by_handle) == 0 && S_ISREG(by_handle.st_mode) &&
                  by_handle.st_nlink == 1 &&
                  fstatat(directory->fd, staged->name, &by_name, AT_SYMLINK_NOFOLLOW) == 0 &&
                  S_ISREG(by_name.st_mode) && by_name.st_dev == by_handle.st_dev &&
                  by_name.st_ino == by_handle.st_ino;
    bool written = opened && artifact_write_all_native(file, data, length) && fsync(file) == 0;
    bool closed = file >= 0 && close(file) == 0;
    if (!opened || !written || !closed) {
        artifact_unlink_child(directory, staged->name);
        file_error_set(out_err, !opened ? "open_temp" : "write_temp", open_error);
        return CBM_NOT_FOUND;
    }
#endif
    staged->exists = true;
    return 0;
}

static int artifact_publish_staged(artifact_directory_t *directory, artifact_staged_file_t *staged,
                                   const char *target, artifact_file_error_t *out_err) {
    file_error_clear(out_err);
    if (!directory || !staged || !staged->exists || !artifact_base_name_valid(target) ||
        !artifact_directory_revalidate(directory)) {
        file_error_set(out_err, "unsafe_parent", 0);
        return CBM_NOT_FOUND;
    }
#ifdef _WIN32
    char temporary[CBM_SZ_4K];
    char destination[CBM_SZ_4K];
    int temporary_length =
        snprintf(temporary, sizeof(temporary), "%s/%s", directory->path, staged->name);
    int destination_length =
        snprintf(destination, sizeof(destination), "%s/%s", directory->path, target);
    bool renamed = temporary_length > 0 && (size_t)temporary_length < sizeof(temporary) &&
                   destination_length > 0 && (size_t)destination_length < sizeof(destination) &&
                   cbm_rename_replace(temporary, destination) == 0;
    DWORD rename_error = renamed ? ERROR_SUCCESS : GetLastError();
    if (!renamed) {
        file_error_set(out_err, "rename_temp", (int)rename_error);
        return CBM_NOT_FOUND;
    }
#else
    if (renameat(directory->fd, staged->name, directory->fd, target) != 0) {
        file_error_set(out_err, "rename_temp", errno);
        return CBM_NOT_FOUND;
    }
#endif
    staged->exists = false;
    if (!artifact_sync_directory(directory)) {
        file_error_set(out_err, "sync_directory", errno);
        return CBM_NOT_FOUND;
    }
    return 0;
}

/* Build path: <repo>/.codebase-memory/<name> into caller-owned buf. */
static bool artifact_path(char *buf, size_t bufsz, const char *repo_path, const char *name) {
    int n = snprintf(buf, bufsz, "%s/%s/%s", repo_path, CBM_ARTIFACT_DIR, name);
    return n >= 0 && (size_t)n < bufsz;
}

/* Read entire file into malloc'd buffer. Sets *out_len. Returns NULL on error. */
static char *read_file_alloc(const char *path, size_t *out_len) {
    if (!path || !out_len) {
        return NULL;
    }
    int64_t file_size = cbm_file_size(path);
    if (file_size <= 0 || (uint64_t)file_size > (uint64_t)SIZE_MAX) {
        return NULL;
    }
    FILE *fp = cbm_fopen(path, "rb");
    if (!fp) {
        return NULL;
    }
    size_t expected = (size_t)file_size;
    char *buf = malloc(expected);
    if (!buf) {
        (void)fclose(fp);
        return NULL;
    }
    size_t rd = fread(buf, ART_NUL, expected, fp);
    int extra = rd == expected ? fgetc(fp) : 0;
    (void)fclose(fp);
    if (rd != expected || extra != EOF) {
        free(buf);
        return NULL;
    }
    *out_len = expected;
    return buf;
}

/* Create and fill one caller-provided mkstemp template. The unique file itself
 * becomes the import staging DB; there is no second predictable `.tmp` name. */
static int write_unique_temp_file(char *path_template, const char *data, size_t length,
                                  artifact_file_error_t *out_err) {
    file_error_clear(out_err);
    int file = cbm_mkstemp(path_template);
    if (file < 0) {
        file_error_set(out_err, "open_temp", errno);
        return CBM_NOT_FOUND;
    }
    size_t offset = 0;
    bool written = true;
    while (offset < length) {
#ifdef _WIN32
        unsigned int chunk =
            length - offset > INT_MAX ? (unsigned int)INT_MAX : (unsigned int)(length - offset);
        int amount = _write(file, data + offset, chunk);
#else
        ssize_t amount = write(file, data + offset, length - offset);
#endif
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            written = false;
            break;
        }
        offset += (size_t)amount;
    }
#ifdef _WIN32
    bool synced = written && _commit(file) == 0;
    bool closed = _close(file) == 0;
#else
    bool synced = written && fsync(file) == 0;
    bool closed = close(file) == 0;
#endif
    if (!written || !synced || !closed) {
        int saved_errno = errno;
        (void)cbm_unlink(path_template);
        file_error_set(out_err, !written ? "write_temp" : (!synced ? "sync_temp" : "close_temp"),
                       saved_errno);
        return CBM_NOT_FOUND;
    }
    return 0;
}

#ifdef _WIN32
#define ARTIFACT_NULL_DEV "NUL"
#else
#define ARTIFACT_NULL_DEV "/dev/null"
#endif

/* See artifact.h. Mirrors git_context.c's git_validate_repo_path (the best-hardened
 * git shell-out): cbm_validate_shell_arg rejects quote / backslash / substitution
 * metacharacters, and on Windows we also reject the cmd.exe expansion metacharacters
 * % ! ^. Callers then use DOUBLE quotes (honored by both POSIX sh and cmd.exe, unlike
 * single quotes on cmd.exe), so a repo path may legitimately contain spaces. */
bool cbm_artifact_repo_path_is_shell_safe(const char *repo_path) {
    if (!cbm_validate_shell_arg(repo_path)) {
        return false;
    }
#ifdef _WIN32
    for (const char *p = repo_path; *p; p++) {
        if (*p == '%' || *p == '!' || *p == '^') {
            return false;
        }
    }
#endif
    return true;
}

/* Get current git HEAD hash. buf must be >= CBM_SZ_64. Returns false on error. */
static bool git_head_hash(const char *repo_path, char *buf, size_t bufsz) {
    char cmd[CBM_SZ_1K];
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        buf[0] = '\0';
        return false;
    }
    int n =
        snprintf(cmd, sizeof(cmd), "git -C \"%s\" rev-parse HEAD 2>" ARTIFACT_NULL_DEV, repo_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        buf[0] = '\0'; /* truncated command → don't run a malformed shell string (parity with
                          git_context.c) */
        return false;
    }
    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
        buf[0] = '\0';
        return false;
    }
    buf[0] = '\0';
    if (fgets(buf, (int)bufsz, fp)) {
        /* Strip trailing newline */
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - ART_NUL] == '\n' || buf[len - ART_NUL] == '\r')) {
            buf[--len] = '\0';
        }
    }
    (void)cbm_pclose(fp);
    return buf[0] != '\0';
}

/* Generate ISO 8601 timestamp into buf. */
static void iso_timestamp(char *buf, size_t bufsz) {
    time_t now = time(NULL);
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    (void)strftime(buf, bufsz, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ── Metadata read/write ─────────────────────────────────────────── */

static yyjson_doc *read_metadata_document(const artifact_directory_t *directory) {
    size_t len = 0;
    char *json = artifact_read_file_alloc(directory, CBM_ARTIFACT_META, CBM_SZ_64K, &len);
    if (!json) {
        return NULL;
    }
    yyjson_doc *doc = yyjson_read(json, len, 0);
    free(json);
    return doc;
}

typedef struct {
    size_t original_size;
    size_t compressed_size;
    char payload_sha256[CBM_SHA256_HEX_LEN + 1];
} artifact_metadata_t;

static bool artifact_sha256_string_valid(const char *digest) {
    if (!digest || strlen(digest) != CBM_SHA256_HEX_LEN) {
        return false;
    }
    for (size_t i = 0; i < CBM_SHA256_HEX_LEN; i++) {
        if (!((digest[i] >= '0' && digest[i] <= '9') || (digest[i] >= 'a' && digest[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool metadata_parse(const yyjson_doc *doc, artifact_metadata_t *metadata) {
    if (!doc || !metadata) {
        return false;
    }
    memset(metadata, 0, sizeof(*metadata));
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *version = yyjson_is_obj(root) ? yyjson_obj_get(root, "schema_version") : NULL;
    yyjson_val *original = yyjson_is_obj(root) ? yyjson_obj_get(root, "original_size") : NULL;
    yyjson_val *compressed = yyjson_is_obj(root) ? yyjson_obj_get(root, "compressed_size") : NULL;
    yyjson_val *digest = yyjson_is_obj(root) ? yyjson_obj_get(root, "payload_sha256") : NULL;
    if (!version || !yyjson_is_int(version) ||
        yyjson_get_int(version) != CBM_ARTIFACT_SCHEMA_VERSION || !original ||
        !yyjson_is_uint(original) || !compressed || !yyjson_is_uint(compressed) || !digest ||
        !yyjson_is_str(digest)) {
        return false;
    }
    uint64_t original_value = yyjson_get_uint(original);
    uint64_t compressed_value = yyjson_get_uint(compressed);
    const char *digest_value = yyjson_get_str(digest);
    if (original_value == 0 || original_value > SIZE_MAX ||
        original_value > ART_MAX_DECOMPRESSED_BYTES || compressed_value == 0 ||
        compressed_value > SIZE_MAX || !artifact_sha256_string_valid(digest_value)) {
        return false;
    }
    size_t original_size = (size_t)original_value;
    size_t max_compressed = cbm_zstd_compress_bound(original_size);
    if (max_compressed == 0 || compressed_value > max_compressed) {
        return false;
    }
    metadata->original_size = original_size;
    metadata->compressed_size = (size_t)compressed_value;
    memcpy(metadata->payload_sha256, digest_value, CBM_SHA256_HEX_LEN + 1U);
    return true;
}

static bool artifact_read_valid_bundle(const artifact_directory_t *directory,
                                       yyjson_doc **document_out, artifact_metadata_t *metadata_out,
                                       char **payload_out, size_t *payload_size_out) {
    if (!document_out || !metadata_out || !payload_out || !payload_size_out) {
        return false;
    }
    *document_out = NULL;
    *payload_out = NULL;
    *payload_size_out = 0;
    yyjson_doc *document = read_metadata_document(directory);
    artifact_metadata_t metadata;
    if (!metadata_parse(document, &metadata)) {
        if (document) {
            yyjson_doc_free(document);
        }
        return false;
    }
    size_t payload_size = 0;
    char *payload = artifact_read_file_alloc(directory, CBM_ARTIFACT_FILENAME,
                                             metadata.compressed_size, &payload_size);
    char digest[CBM_SHA256_HEX_LEN + 1];
    if (!payload || payload_size != metadata.compressed_size) {
        free(payload);
        yyjson_doc_free(document);
        return false;
    }
    cbm_sha256_hex(payload, payload_size, digest);
    if (strcmp(digest, metadata.payload_sha256) != 0) {
        free(payload);
        yyjson_doc_free(document);
        return false;
    }
    *document_out = document;
    *metadata_out = metadata;
    *payload_out = payload;
    *payload_size_out = payload_size;
    return true;
}

/* Encode the manifest before either final name is changed. */
static char *build_metadata_json(const char *repo_path, const char *project_name, int nodes,
                                 int edges, size_t original_size, size_t compressed_size,
                                 int compression_level, const char *payload_sha256,
                                 size_t *json_len_out) {
    char commit[CBM_SZ_64] = "";
    git_head_hash(repo_path, commit, sizeof(commit));

    char ts[CBM_SZ_64];
    iso_timestamp(ts, sizeof(ts));

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    yyjson_mut_obj_add_int(doc, root, "schema_version", CBM_ARTIFACT_SCHEMA_VERSION);
    yyjson_mut_obj_add_str(doc, root, "commit", commit);
    yyjson_mut_obj_add_str(doc, root, "indexed_at", ts);
    yyjson_mut_obj_add_str(doc, root, "project", project_name);
    yyjson_mut_obj_add_int(doc, root, "nodes", nodes);
    yyjson_mut_obj_add_int(doc, root, "edges", edges);
    yyjson_mut_obj_add_uint(doc, root, "original_size", (uint64_t)original_size);
    yyjson_mut_obj_add_uint(doc, root, "compressed_size", (uint64_t)compressed_size);
    yyjson_mut_obj_add_str(doc, root, "payload_sha256", payload_sha256);
    yyjson_mut_obj_add_int(doc, root, "compression_level", compression_level);

    char *json = yyjson_mut_write(doc, YYJSON_WRITE_PRETTY, json_len_out);
    yyjson_mut_doc_free(doc);
    if (!json) {
        (void)artifact_export_fail("write_metadata", NULL, "json_encode", 0);
    }
    return json;
}

/* ── .gitattributes setup ────────────────────────────────────────── */

static void configure_merge_driver(const char *repo_path) {
    /* Best-effort: configure merge driver */
    if (!cbm_artifact_repo_path_is_shell_safe(repo_path)) {
        return;
    }
    char cmd[CBM_SZ_1K];
    int n = snprintf(cmd, sizeof(cmd),
                     "git -C \"%s\" config merge.ours.driver true 2>" ARTIFACT_NULL_DEV, repo_path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        return; /* truncated command → skip (parity with git_context.c) */
    }
    FILE *p = cbm_popen(cmd, "r");
    if (p) {
        (void)cbm_pclose(p);
    }
}

/* ── Index stripping ─────────────────────────────────────────────── */

/* SQL to drop all user-created indexes (not autoindexes, not FTS5). */
static const char *DROP_INDEXES_SQL = "DROP INDEX IF EXISTS idx_nodes_label;"
                                      "DROP INDEX IF EXISTS idx_nodes_name;"
                                      "DROP INDEX IF EXISTS idx_nodes_file;"
                                      "DROP INDEX IF EXISTS idx_edges_source;"
                                      "DROP INDEX IF EXISTS idx_edges_target;"
                                      "DROP INDEX IF EXISTS idx_edges_type;"
                                      "DROP INDEX IF EXISTS idx_edges_target_type;"
                                      "DROP INDEX IF EXISTS idx_edges_source_type;"
                                      "DROP INDEX IF EXISTS idx_edges_url_path;";

/* ── Export helpers ───────────────────────────────────────────────── */

static void cleanup_snapshot_directory(const char *directory, const char *db_path) {
    if (db_path && db_path[0]) {
        static const char *const suffixes[] = {"", "-wal", "-shm", "-journal"};
        for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
            char path[CBM_SZ_4K];
            int written = snprintf(path, sizeof(path), "%s%s", db_path, suffixes[i]);
            if (written > 0 && (size_t)written < sizeof(path)) {
                (void)cbm_unlink(path);
            }
        }
    }
    if (directory && directory[0]) {
        (void)cbm_rmdir(directory);
    }
}

/* Prepare a stripped DB copy for best-quality export.
 * VACUUM INTO → (optionally) drop indexes → VACUUM. Returns malloc'd buffer
 * or NULL. VACUUM INTO runs on BOTH quality levels: it is the consistent
 * snapshot — the store runs in WAL mode, so raw main-file bytes miss
 * committed transactions still in the -wal and can be mid-checkpoint torn
 * (#895). Only the index-stripping is BEST-only. */
static char *prepare_snapshot_db(const char *db_path, size_t *out_size, bool strip_indexes) {
    if (out_size) {
        *out_size = 0;
    }
    char snapshot_dir[CBM_SZ_4K];
    int directory_written =
        snprintf(snapshot_dir, sizeof(snapshot_dir), "%s/cbm-artifact-XXXXXX", cbm_tmpdir());
    if (directory_written <= 0 || (size_t)directory_written >= sizeof(snapshot_dir) ||
        !cbm_mkdtemp(snapshot_dir)) {
        artifact_export_fail("prepare_snapshot_dir", cbm_tmpdir(), "mkdtemp", errno);
        return NULL;
    }
    char tmp_path[CBM_SZ_4K];
    int path_written = snprintf(tmp_path, sizeof(tmp_path), "%s/snapshot.db", snapshot_dir);
    if (path_written <= 0 || (size_t)path_written >= sizeof(tmp_path)) {
        artifact_export_fail("prepare_snapshot_path", snapshot_dir, "path_too_long", 0);
        cleanup_snapshot_directory(snapshot_dir, NULL);
        return NULL;
    }
    if (g_snapshot_path_hook) {
        g_snapshot_path_hook(tmp_path, g_snapshot_path_hook_context);
    }

    /* VACUUM INTO: clean compacted copy. Use raw sqlite3 to bypass store authorizer
     * (which blocks ATTACH, used internally by VACUUM INTO). */
    sqlite3 *raw_db = NULL;
    if (sqlite3_open_v2(db_path, &raw_db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        const char *err = raw_db ? sqlite3_errmsg(raw_db) : "sqlite_open";
        artifact_export_fail("open_source_db", db_path, err, 0);
        sqlite3_close(raw_db);
        cleanup_snapshot_directory(snapshot_dir, tmp_path);
        return NULL;
    }

    char *vacuum_sql = sqlite3_mprintf("VACUUM INTO %Q;", tmp_path);
    if (!vacuum_sql) {
        sqlite3_close(raw_db);
        artifact_export_fail("vacuum_into", tmp_path, "sql_alloc", 0);
        cleanup_snapshot_directory(snapshot_dir, tmp_path);
        return NULL;
    }
    char *errmsg = NULL;
    int vrc = sqlite3_exec(raw_db, vacuum_sql, NULL, NULL, &errmsg);
    sqlite3_free(vacuum_sql);
    sqlite3_close(raw_db);

    if (vrc != SQLITE_OK) {
        artifact_export_fail("vacuum_into", tmp_path, errmsg ? errmsg : sqlite3_errstr(vrc), 0);
        sqlite3_free(errmsg);
        cleanup_snapshot_directory(snapshot_dir, tmp_path);
        return NULL;
    }

    /* Strip indexes from the copy for better compression (BEST only). */
    if (strip_indexes) {
        sqlite3 *tmp_db = NULL;
        if (sqlite3_open_v2(tmp_path, &tmp_db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK) {
            sqlite3_exec(tmp_db, DROP_INDEXES_SQL, NULL, NULL, NULL);
            sqlite3_exec(tmp_db, "VACUUM;", NULL, NULL, NULL);
            sqlite3_close(tmp_db);
        }
    }

    /* Reopened by path rather than held on a descriptor across VACUUM INTO,
     * because sqlite owns the create. The private directory is what makes that
     * safe: an attacker who cannot enter it cannot swap the file underneath. */
    char *data = read_file_alloc(tmp_path, out_size);
    if (!data || *out_size == 0) {
        artifact_export_fail("read_stripped_db", tmp_path, "empty_or_unreadable", errno);
    }
    cleanup_snapshot_directory(snapshot_dir, tmp_path);
    return data;
}

/* ── Export ───────────────────────────────────────────────────────── */

int cbm_artifact_export(const char *db_path, const char *repo_path, const char *project_name,
                        int quality) {
    clear_export_error();

    if (!db_path || !repo_path || !project_name) {
        return artifact_export_fail("validate_args", NULL, "missing_argument", 0);
    }

    artifact_directory_t directory;
    if (!artifact_directory_open(repo_path, true, &directory)) {
        return artifact_export_fail("prepare_artifact_dir", repo_path, "unsafe_or_unopenable",
                                    errno);
    }
    if (!artifact_create_gitattributes(&directory)) {
        artifact_directory_close(&directory);
        return artifact_export_fail("prepare_gitattributes", repo_path, "unsafe_or_unwritable",
                                    errno);
    }
    if (!artifact_lock_acquire(&directory, true)) {
        artifact_directory_close(&directory);
        return artifact_export_fail("lock_bundle", repo_path, "unsafe_or_unavailable", errno);
    }

    size_t db_size = 0;
    char *db_data = NULL;
    int compression_level = ART_ZSTD_FAST;

    if (quality == CBM_ARTIFACT_BEST) {
        compression_level = ART_ZSTD_BEST;
        db_data = prepare_snapshot_db(db_path, &db_size, true);
    } else {
        /* FAST keeps zstd-3 and its indexes, but still snapshots via
         * VACUUM INTO: the raw main-file bytes of a live WAL store are a
         * torn copy (#895). */
        db_data = prepare_snapshot_db(db_path, &db_size, false);
    }

    if (!db_data || db_size == 0) {
        free(db_data);
        if (cbm_artifact_export_last_error()) {
            artifact_directory_close(&directory);
            return CBM_NOT_FOUND;
        }
        artifact_directory_close(&directory);
        return artifact_export_fail("read_db", db_path, "empty_or_unreadable", errno);
    }

    /* Compress with zstd */
    size_t bound = cbm_zstd_compress_bound(db_size);
    if (bound == 0) {
        free(db_data);
        artifact_directory_close(&directory);
        return artifact_export_fail("compress", NULL, "zstd_compress_bound", 0);
    }
    char *compressed = malloc(bound);
    if (!compressed) {
        free(db_data);
        artifact_directory_close(&directory);
        return artifact_export_fail("compress", NULL, "alloc_compressed_buffer", 0);
    }

    size_t clen = cbm_zstd_compress(db_data, db_size, compressed, bound, compression_level);
    free(db_data);

    if (clen == 0) {
        free(compressed);
        artifact_directory_close(&directory);
        return artifact_export_fail("compress", NULL, "zstd_compress", 0);
    }

    char payload_sha256[CBM_SHA256_HEX_LEN + 1];
    cbm_sha256_hex(compressed, clen, payload_sha256);

    /* Get node/edge counts before publication so both final names remain on
     * the prior generation until the complete next bundle has been staged. */
    int nodes = 0;
    int edges = 0;
    cbm_store_t *count_store = cbm_store_open_path_query(db_path);
    if (count_store) {
        nodes = cbm_store_count_nodes(count_store, project_name);
        edges = cbm_store_count_edges(count_store, project_name);
        cbm_store_close(count_store);
    }

    size_t metadata_length = 0;
    char *metadata = build_metadata_json(repo_path, project_name, nodes, edges, db_size, clen,
                                         compression_level, payload_sha256, &metadata_length);
    if (!metadata || metadata_length == 0) {
        free(metadata);
        free(compressed);
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }

    /* Fully write and sync BOTH unique staging files before changing either
     * final name. The payload is published first and its digest-bound manifest
     * last, so an interrupted publish is unservable rather than mixed. */
    char zst_path[CBM_SZ_4K];
    if (!artifact_path(zst_path, sizeof(zst_path), repo_path, CBM_ARTIFACT_FILENAME)) {
        free(metadata);
        free(compressed);
        artifact_directory_close(&directory);
        return artifact_export_fail("write_artifact", repo_path, "path_too_long", 0);
    }
    char metadata_path[CBM_SZ_4K];
    if (!artifact_path(metadata_path, sizeof(metadata_path), repo_path, CBM_ARTIFACT_META)) {
        free(metadata);
        free(compressed);
        artifact_directory_close(&directory);
        return artifact_export_fail("write_metadata", repo_path, "path_too_long", 0);
    }

    artifact_file_error_t ioerr;
    artifact_staged_file_t payload_stage = {0};
    artifact_staged_file_t metadata_stage = {0};
    int wrc = artifact_stage_file(&directory, CBM_ARTIFACT_FILENAME, compressed, clen,
                                  &payload_stage, &ioerr);
    free(compressed);
    if (wrc != 0) {
        free(metadata);
        artifact_directory_close(&directory);
        return artifact_export_fail("write_artifact", zst_path, ioerr.err, ioerr.err_no);
    }

    wrc = artifact_stage_file(&directory, CBM_ARTIFACT_META, metadata, metadata_length,
                              &metadata_stage, &ioerr);
    free(metadata);
    if (wrc != 0) {
        artifact_staged_discard(&directory, &payload_stage);
        artifact_directory_close(&directory);
        return artifact_export_fail("write_metadata", metadata_path, ioerr.err, ioerr.err_no);
    }

    wrc = artifact_publish_staged(&directory, &payload_stage, CBM_ARTIFACT_FILENAME, &ioerr);
    if (wrc != 0) {
        artifact_staged_discard(&directory, &payload_stage);
        artifact_staged_discard(&directory, &metadata_stage);
        artifact_directory_close(&directory);
        return artifact_export_fail("write_artifact", zst_path, ioerr.err, ioerr.err_no);
    }
    if (g_payload_published_hook) {
        g_payload_published_hook(project_name, g_payload_published_hook_context);
    }

    if (artifact_publish_staged(&directory, &metadata_stage, CBM_ARTIFACT_META, &ioerr) != 0) {
        /* The new payload may already be durable. Never delete it here: doing
         * so could erase a previously published name. The old manifest will
         * fail its size/digest binding until the next successful export. */
        artifact_staged_discard(&directory, &metadata_stage);
        artifact_directory_close(&directory);
        return artifact_export_fail("write_metadata", metadata_path, ioerr.err, ioerr.err_no);
    }

    /* Ensure .gitattributes for merge conflict prevention */
    configure_merge_driver(repo_path);

    double ratio = db_size > 0 ? (double)db_size / (double)clen : 0.0;
    cbm_log_info("artifact.export", "quality", quality == CBM_ARTIFACT_BEST ? "best" : "fast",
                 "original_mb", itoa_buf((int)(db_size / ART_BYTES_PER_MB)), "compressed_mb",
                 itoa_buf((int)(clen / ART_BYTES_PER_MB)), "ratio",
                 itoa_buf((int)(ratio * ART_RATIO_SCALE)));

    artifact_directory_close(&directory);
    return 0;
}

/* ── Import ──────────────────────────────────────────────────────── */

static void cleanup_import_temp(const char *path) {
    if (path && path[0]) {
        (void)cbm_remove_db_sidecars(path);
        (void)cbm_unlink(path);
    }
}

/* Fail closed on every pre-existing destination entry, including a no-follow
 * symlink/reparse point and SQLite sidecars. Import is install-only: it never
 * removes or replaces another cache generation. */
static bool artifact_path_entry_absent(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
#ifdef _WIN32
    wchar_t *wide = cbm_path_to_wide(path);
    if (!wide) {
        return false;
    }
    HANDLE entry = CreateFileW(
        wide, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    DWORD error = entry == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (entry != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(entry);
    }
    free(wide);
    return entry == INVALID_HANDLE_VALUE &&
           (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
#else
    struct stat status;
    if (lstat(path, &status) == 0) {
        return false;
    }
    return errno == ENOENT || errno == ENOTDIR;
#endif
}

static bool artifact_cache_destination_absent(const char *cache_db_path) {
    static const char *const suffixes[] = {"", "-wal", "-shm", "-journal"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        char path[CBM_SZ_4K];
        int written = snprintf(path, sizeof(path), "%s%s", cache_db_path, suffixes[i]);
        if (written <= 0 || (size_t)written >= sizeof(path) || !artifact_path_entry_absent(path)) {
            return false;
        }
    }
    return true;
}

#ifndef _WIN32
static bool artifact_sync_path_parent(const char *path) {
    char parent[CBM_SZ_4K];
    int written = snprintf(parent, sizeof(parent), "%s", path ? path : "");
    if (written <= 0 || (size_t)written >= sizeof(parent)) {
        return false;
    }
    char *slash = strrchr(parent, '/');
    if (!slash) {
        memcpy(parent, ".", 2);
    } else if (slash == parent) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    int flags = O_RDONLY | O_DIRECTORY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int directory = open(parent, flags);
    if (directory < 0) {
        return false;
    }
    int result;
    do {
        result = fsync(directory);
    } while (result != 0 && errno == EINTR);
    int sync_error = errno;
    bool closed = close(directory) == 0;
    return closed &&
           (result == 0 || sync_error == EINVAL || sync_error == ENOTSUP || sync_error == EROFS);
}
#endif

static bool artifact_install_cache_no_replace(const char *temporary, const char *destination) {
#ifdef _WIN32
    wchar_t *source = cbm_path_to_wide(temporary);
    wchar_t *target = cbm_path_to_wide(destination);
    BOOL moved = source && target && MoveFileExW(source, target, MOVEFILE_WRITE_THROUGH);
    free(source);
    free(target);
    return moved != 0;
#else
    if (link(temporary, destination) != 0) {
        return false;
    }
    bool unlinked = unlink(temporary) == 0;
    bool synced = artifact_sync_path_parent(destination);
    return unlinked && synced;
#endif
}

int cbm_artifact_import(const char *repo_path, const char *cache_db_path) {
    if (!repo_path || !cache_db_path) {
        return CBM_NOT_FOUND;
    }
    if (!artifact_cache_destination_absent(cache_db_path)) {
        cbm_log_info("artifact.import", "skip", "cache_destination_exists");
        return CBM_NOT_FOUND;
    }

    artifact_directory_t directory;
    if (!artifact_directory_open(repo_path, false, &directory) ||
        !artifact_lock_acquire(&directory, false)) {
        artifact_directory_close(&directory);
        cbm_log_error("artifact.import", "err", "unsafe_or_unlocked_bundle");
        return CBM_NOT_FOUND;
    }

    /* Metadata and payload are one digest-bound schema-v3 bundle. Keep one
     * shared repository lock across validation and cache publication so an
     * exporter cannot advance the source generation beneath this import. */
    yyjson_doc *metadata_document = NULL;
    artifact_metadata_t metadata;
    size_t clen = 0;
    char *compressed = NULL;
    if (!artifact_read_valid_bundle(&directory, &metadata_document, &metadata, &compressed,
                                    &clen)) {
        cbm_log_error("artifact.import", "err", "invalid_artifact_bundle");
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }
    yyjson_doc_free(metadata_document);

    /* Decompress */
    /* Size the destination from the zstd frame's own content-size header, not
     * from the separately-stored (attacker-controllable) original_size field.
     * The allocation and the decoder capacity are then the SAME size_t value,
     * so a crafted size can never make the capacity exceed the real buffer
     * (the int-truncation that used to do exactly that is gone with the size_t
     * signature). Require the metadata field to agree, and cap the total. */
    size_t frame_size = cbm_zstd_frame_content_size(compressed, clen);
    if (frame_size == 0 || frame_size > ART_MAX_DECOMPRESSED_BYTES ||
        frame_size != metadata.original_size) {
        free(compressed);
        artifact_directory_close(&directory);
        cbm_log_error("artifact.import", "err", "bad_decompressed_size");
        return CBM_NOT_FOUND;
    }

    char *decompressed = malloc(frame_size);
    if (!decompressed) {
        free(compressed);
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }

    int64_t dlen = cbm_zstd_decompress(compressed, clen, decompressed, frame_size);
    free(compressed);

    if (dlen <= 0 || (size_t)dlen != frame_size) {
        free(decompressed);
        artifact_directory_close(&directory);
        cbm_log_error("artifact.import", "err", "zstd_decompress");
        return CBM_NOT_FOUND;
    }

    /* Each concurrent reader gets its own staging file. Keep the artifact SH
     * lock through cache publication: an exporter cannot advance the source
     * generation and let an older import publish last. */
    char tmp_path[CBM_SZ_4K];
    int temp_written = snprintf(tmp_path, sizeof(tmp_path), "%s.import-XXXXXX", cache_db_path);
    if (temp_written <= 0 || (size_t)temp_written >= sizeof(tmp_path)) {
        free(decompressed);
        artifact_directory_close(&directory);
        cbm_log_error("artifact.import", "err", "temp_path_too_long");
        return CBM_NOT_FOUND;
    }

    /* Ensure cache directory exists */
    char cache_dir[CBM_SZ_4K];
    int cache_written = snprintf(cache_dir, sizeof(cache_dir), "%s", cache_db_path);
    if (cache_written <= 0 || (size_t)cache_written >= sizeof(cache_dir)) {
        free(decompressed);
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }
    char *last_slash = strrchr(cache_dir, '/');
    if (last_slash && last_slash != cache_dir) {
        *last_slash = '\0';
        if (!cbm_mkdir_p(cache_dir, ART_DIR_PERMS)) {
            free(decompressed);
            artifact_directory_close(&directory);
            return CBM_NOT_FOUND;
        }
    }
    if (!artifact_cache_destination_absent(cache_db_path)) {
        free(decompressed);
        artifact_directory_close(&directory);
        cbm_log_info("artifact.import", "skip", "cache_destination_exists");
        return CBM_NOT_FOUND;
    }

    artifact_file_error_t ioerr;
    int wrc = write_unique_temp_file(tmp_path, decompressed, (size_t)dlen, &ioerr);
    free(decompressed);

    if (wrc != 0) {
        if (ioerr.err_no != 0) {
            cbm_log_error("artifact.import", "err", "write_temp_db", "detail", ioerr.err, "errno",
                          itoa_buf(ioerr.err_no), "path", tmp_path);
        } else {
            cbm_log_error("artifact.import", "err", "write_temp_db", "detail", ioerr.err, "path",
                          tmp_path);
        }
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }

    /* Open with cbm_store_open_path to auto-create missing indexes + FTS5 */
    cbm_store_t *store = cbm_store_open_path(tmp_path);
    if (!store) {
        cbm_log_error("artifact.import", "err", "open_imported_db");
        cleanup_import_temp(tmp_path);
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }

    /* Deep integrity check — refuse corrupted artifacts. The shallow check
     * only sanity-checks the projects table, so page-corrupted (torn)
     * artifacts installed cleanly (#895); quick_check catches them. */
    if (!cbm_store_check_integrity_deep(store)) {
        cbm_log_error("artifact.import", "err", "integrity_check_failed");
        cbm_store_close(store);
        cleanup_import_temp(tmp_path);
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }
    if (cbm_store_prepare_for_publish(store) != CBM_STORE_OK) {
        cbm_log_error("artifact.import", "err", "seal_imported_db_failed");
        cbm_store_close(store);
        cleanup_import_temp(tmp_path);
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }

    cbm_store_close(store);

    /* Seal and clean only our unique staging generation. Recheck all final
     * names immediately before the atomic no-replace install; never unlink a
     * destination main file or sidecar owned by another process. */
    if (cbm_remove_db_sidecars(tmp_path) != 0 ||
        !artifact_cache_destination_absent(cache_db_path) ||
        !artifact_install_cache_no_replace(tmp_path, cache_db_path)) {
        cbm_log_error("artifact.import", "err", "install_cache_no_replace");
        cleanup_import_temp(tmp_path);
        artifact_directory_close(&directory);
        return CBM_NOT_FOUND;
    }

    cbm_log_info("artifact.import", "db", cache_db_path, "size_mb",
                 itoa_buf((int)((size_t)dlen / ART_BYTES_PER_MB)));

    artifact_directory_close(&directory);
    return 0;
}

/* ── Existence check ─────────────────────────────────────────────── */

bool cbm_artifact_exists(const char *repo_path) {
    if (!repo_path) {
        return false;
    }
    artifact_directory_t directory;
    if (!artifact_directory_open(repo_path, false, &directory) ||
        !artifact_lock_acquire(&directory, false)) {
        artifact_directory_close(&directory);
        return false;
    }
    yyjson_doc *document = NULL;
    artifact_metadata_t metadata;
    char *payload = NULL;
    size_t payload_size = 0;
    bool exists =
        artifact_read_valid_bundle(&directory, &document, &metadata, &payload, &payload_size);
    free(payload);
    if (document) {
        yyjson_doc_free(document);
    }
    artifact_directory_close(&directory);
    return exists;
}

/* ── Commit hash extraction ──────────────────────────────────────── */

char *cbm_artifact_commit(const char *repo_path) {
    if (!repo_path) {
        return NULL;
    }
    artifact_directory_t directory;
    if (!artifact_directory_open(repo_path, false, &directory) ||
        !artifact_lock_acquire(&directory, false)) {
        artifact_directory_close(&directory);
        return NULL;
    }
    yyjson_doc *doc = NULL;
    artifact_metadata_t metadata;
    char *payload = NULL;
    size_t payload_size = 0;
    if (!artifact_read_valid_bundle(&directory, &doc, &metadata, &payload, &payload_size)) {
        artifact_directory_close(&directory);
        return NULL;
    }
    free(payload);

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *val = yyjson_obj_get(root, "commit");
    char *result = NULL;
    if (val) {
        const char *s = yyjson_get_str(val);
        if (s && s[0]) {
            size_t slen = strlen(s);
            result = malloc(slen + ART_NUL);
            if (result) {
                memcpy(result, s, slen + ART_NUL);
            }
        }
    }
    yyjson_doc_free(doc);
    artifact_directory_close(&directory);
    return result;
}
