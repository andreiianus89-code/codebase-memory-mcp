#include "foundation/trusted_fs.h"
#include "foundation/trusted_fs_internal.h"

#include "foundation/compat.h"
#include "foundation/constants.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "foundation/win_utf8.h"
#include <windows.h>
#include <wchar.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

struct cbm_trusted_root {
#ifdef _WIN32
    HANDLE handle;
    wchar_t *lexical_path;
    wchar_t *final_path;
    BY_HANDLE_FILE_INFORMATION identity;
    HANDLE *ancestor_handles;
    size_t ancestor_count;
#else
    int fd;
    dev_t device;
    ino_t inode;
#endif
};

static bool trusted_rel_path_valid(const char *path) {
    if (!path || !path[0] || path[0] == '/') {
        return false;
    }
#ifdef _WIN32
    if (path[0] == '\\' || path[1] == ':') {
        return false;
    }
#endif
    const char *component = path;
    for (const char *p = path;; p++) {
        bool separator = *p == '/';
#ifdef _WIN32
        separator = separator || *p == '\\';
#endif
        if (*p != '\0' && !separator) {
#ifdef _WIN32
            if (*p == ':') {
                return false;
            }
#endif
            continue;
        }
        size_t len = (size_t)(p - component);
        if (len == 0 || (len == 1 && component[0] == '.') ||
            (len == 2 && component[0] == '.' && component[1] == '.')) {
            return false;
        }
        if (*p == '\0') {
            return true;
        }
        component = p + 1;
    }
}

#ifdef _WIN32

static wchar_t *trusted_win_final_path(HANDLE handle) {
    DWORD needed = GetFinalPathNameByHandleW(handle, NULL, 0, FILE_NAME_NORMALIZED);
    if (needed == 0 || needed > INT_MAX) {
        return NULL;
    }
    wchar_t *path = (wchar_t *)calloc((size_t)needed + 1, sizeof(*path));
    if (!path) {
        return NULL;
    }
    DWORD written = GetFinalPathNameByHandleW(handle, path, needed + 1, FILE_NAME_NORMALIZED);
    if (written == 0 || written > needed) {
        free(path);
        return NULL;
    }
    while (written > 1 && (path[written - 1] == L'\\' || path[written - 1] == L'/')) {
        path[--written] = L'\0';
    }
    return path;
}

static bool trusted_win_path_below(const wchar_t *root, const wchar_t *candidate) {
    if (!root || !candidate) {
        return false;
    }
    size_t root_len = wcslen(root);
    size_t candidate_len = wcslen(candidate);
    if (root_len >= candidate_len || root_len > INT_MAX ||
        CompareStringOrdinal(candidate, (int)root_len, root, (int)root_len, FALSE) != CSTR_EQUAL) {
        return false;
    }
    return candidate[root_len] == L'\\' || candidate[root_len] == L'/';
}

static bool trusted_win_same_identity(const BY_HANDLE_FILE_INFORMATION *left,
                                      const BY_HANDLE_FILE_INFORMATION *right) {
    return left && right && left->dwVolumeSerialNumber == right->dwVolumeSerialNumber &&
           left->nFileIndexHigh == right->nFileIndexHigh &&
           left->nFileIndexLow == right->nFileIndexLow;
}

static CBM_TLS cbm_trusted_root_before_final_open_hook_fn trusted_win_before_final_open_hook;
static CBM_TLS void *trusted_win_before_final_open_context;
static CBM_TLS unsigned int trusted_win_directory_open_failures_for_test;

void cbm_trusted_root_set_before_final_open_hook_for_test(
    cbm_trusted_root_before_final_open_hook_fn hook, void *context) {
    trusted_win_before_final_open_hook = hook;
    trusted_win_before_final_open_context = context;
}

static DWORD trusted_win_final_open_flags(void) {
    return FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN;
}

uint32_t cbm_trusted_root_final_open_flags_for_test(void) {
    return (uint32_t)trusted_win_final_open_flags();
}

void cbm_trusted_root_directory_open_failures_set_for_test(unsigned int count) {
    trusted_win_directory_open_failures_for_test = count;
}

static HANDLE trusted_win_open_directory(const wchar_t *path, DWORD access, DWORD share) {
    for (unsigned int attempt = 0; attempt < 10; attempt++) {
        DWORD error;
        if (trusted_win_directory_open_failures_for_test > 0) {
            trusted_win_directory_open_failures_for_test--;
            error = ERROR_SHARING_VIOLATION;
        } else {
            HANDLE handle =
                CreateFileW(path, access, share, NULL, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (handle != INVALID_HANDLE_VALUE) {
                return handle;
            }
            error = GetLastError();
        }
        if (error != ERROR_SHARING_VIOLATION || attempt == 9) {
            SetLastError(error);
            return INVALID_HANDLE_VALUE;
        }
        Sleep(50);
    }
    return INVALID_HANDLE_VALUE;
}

static void trusted_win_close_ancestors(HANDLE *handles, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (handles[i] != INVALID_HANDLE_VALUE) {
            CloseHandle(handles[i]);
        }
    }
    free(handles);
}

static bool trusted_win_pin_ancestors(wchar_t *path, DWORD share, HANDLE **out_handles,
                                      size_t *out_count) {
    if (!path || !out_handles || !out_count) {
        return false;
    }
    *out_handles = NULL;
    *out_count = 0;
    for (wchar_t *p = path; *p; p++) {
        if (*p == L'/') {
            *p = L'\\';
        }
    }
    size_t length = wcslen(path);
    size_t start = 0;
    if (length >= 7 && wcsncmp(path, L"\\\\?\\", 4) == 0 && path[5] == L':' && path[6] == L'\\') {
        start = 7;
    } else if (length >= 3 && path[1] == L':' && path[2] == L'\\') {
        start = 3;
    } else {
        return false; /* strict mode supports local absolute worktrees only */
    }
    HANDLE *handles = NULL;
    size_t count = 0;
    for (size_t i = start; i < length; i++) {
        if (path[i] != L'\\' || i + 1 >= length) {
            continue;
        }
        wchar_t saved = path[i];
        path[i] = L'\0';
        HANDLE handle =
            trusted_win_open_directory(path, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, share);
        path[i] = saved;
        FILE_ATTRIBUTE_TAG_INFO tag = {0};
        bool valid =
            handle != INVALID_HANDLE_VALUE &&
            GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) &&
            (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
        if (!valid) {
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
            trusted_win_close_ancestors(handles, count);
            return false;
        }
        HANDLE *grown = (HANDLE *)realloc(handles, (count + 1) * sizeof(*grown));
        if (!grown) {
            CloseHandle(handle);
            trusted_win_close_ancestors(handles, count);
            return false;
        }
        handles = grown;
        handles[count++] = handle;
    }
    *out_handles = handles;
    *out_count = count;
    return true;
}

static time_t trusted_win_filetime_seconds(FILETIME value) {
    uint64_t ticks = ((uint64_t)value.dwHighDateTime << 32) | (uint64_t)value.dwLowDateTime;
    static const uint64_t unix_epoch_ticks = UINT64_C(116444736000000000);
    if (ticks <= unix_epoch_ticks) {
        return (time_t)0;
    }
    return (time_t)((ticks - unix_epoch_ticks) / UINT64_C(10000000));
}

static int trusted_win_root_open(const char *root_path, cbm_trusted_root_t **out) {
    if (!root_path || !out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    wchar_t *wide = cbm_path_to_wide(root_path);
    if (!wide) {
        return CBM_NOT_FOUND;
    }
    HANDLE *ancestor_handles = NULL;
    size_t ancestor_count = 0;
    if (!trusted_win_pin_ancestors(wide, FILE_SHARE_READ, &ancestor_handles, &ancestor_count)) {
        free(wide);
        return CBM_NOT_FOUND;
    }
    HANDLE handle = trusted_win_open_directory(wide, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                                               FILE_SHARE_READ);
    if (handle == INVALID_HANDLE_VALUE) {
        trusted_win_close_ancestors(ancestor_handles, ancestor_count);
        free(wide);
        return CBM_NOT_FOUND;
    }
    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    BY_HANDLE_FILE_INFORMATION identity = {0};
    wchar_t *final_path = trusted_win_final_path(handle);
    bool valid = GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) &&
                 !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                 (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                 GetFileInformationByHandle(handle, &identity) && final_path;
    if (!valid) {
        free(final_path);
        CloseHandle(handle);
        trusted_win_close_ancestors(ancestor_handles, ancestor_count);
        free(wide);
        return CBM_NOT_FOUND;
    }
    cbm_trusted_root_t *root = (cbm_trusted_root_t *)calloc(1, sizeof(*root));
    if (!root) {
        free(final_path);
        CloseHandle(handle);
        trusted_win_close_ancestors(ancestor_handles, ancestor_count);
        free(wide);
        return CBM_NOT_FOUND;
    }
    root->handle = handle;
    root->lexical_path = wide;
    root->final_path = final_path;
    root->identity = identity;
    root->ancestor_handles = ancestor_handles;
    root->ancestor_count = ancestor_count;
    *out = root;
    return 0;
}

int cbm_trusted_root_open(const char *root_path, cbm_trusted_root_t **out) {
    return trusted_win_root_open(root_path, out);
}

void cbm_trusted_root_close(cbm_trusted_root_t *root) {
    if (!root) {
        return;
    }
    if (root->handle && root->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(root->handle);
    }
    trusted_win_close_ancestors(root->ancestor_handles, root->ancestor_count);
    free(root->lexical_path);
    free(root->final_path);
    free(root);
}

bool cbm_trusted_root_matches_path(const cbm_trusted_root_t *root, const char *path) {
    if (!root || !path) {
        return false;
    }
    wchar_t *wide = cbm_path_to_wide(path);
    if (!wide) {
        return false;
    }
    HANDLE handle = trusted_win_open_directory(wide, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                                               FILE_SHARE_READ);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    BY_HANDLE_FILE_INFORMATION identity = {0};
    bool matches = GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) &&
                   !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                   GetFileInformationByHandle(handle, &identity) &&
                   trusted_win_same_identity(&root->identity, &identity);
    CloseHandle(handle);
    return matches;
}

int cbm_trusted_root_open_mutable_ancestors(const char *root_path, cbm_trusted_root_t **out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    cbm_trusted_root_t *root = NULL;
    if (trusted_win_root_open(root_path, &root) != 0) {
        return CBM_NOT_FOUND;
    }
    HANDLE *mutable_ancestors = NULL;
    size_t mutable_count = 0;
    if (!trusted_win_pin_ancestors(root->lexical_path, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   &mutable_ancestors, &mutable_count) ||
        !cbm_trusted_root_matches_path(root, root_path)) {
        trusted_win_close_ancestors(mutable_ancestors, mutable_count);
        cbm_trusted_root_close(root);
        return CBM_NOT_FOUND;
    }
    trusted_win_close_ancestors(root->ancestor_handles, root->ancestor_count);
    root->ancestor_handles = mutable_ancestors;
    root->ancestor_count = mutable_count;
    *out = root;
    return 0;
}

int cbm_trusted_root_upgrade_mutable_children(cbm_trusted_root_t *root, const char *root_path) {
    if (!root || !root_path || !cbm_trusted_root_matches_path(root, root_path)) {
        return CBM_NOT_FOUND;
    }
    if (trusted_win_before_final_open_hook) {
        trusted_win_before_final_open_hook(trusted_win_before_final_open_context);
    }
    HANDLE mutable =
        trusted_win_open_directory(root->lexical_path, FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE);
    FILE_ATTRIBUTE_TAG_INFO tag = {0};
    BY_HANDLE_FILE_INFORMATION identity = {0};
    bool valid = mutable != INVALID_HANDLE_VALUE &&
                 GetFileInformationByHandleEx(mutable, FileAttributeTagInfo, &tag, sizeof(tag)) &&
                 !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                 (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                 GetFileInformationByHandle(mutable, &identity) &&
                 trusted_win_same_identity(&root->identity, &identity);
    if (!valid) {
        if (mutable != INVALID_HANDLE_VALUE) {
            CloseHandle(mutable);
        }
        return CBM_NOT_FOUND;
    }
    HANDLE strict = root->handle;
    root->handle = mutable;
    CloseHandle(strict);
    return 0;
}

int cbm_trusted_root_dup_native_fd(const cbm_trusted_root_t *root) {
    (void)root;
    return -1;
}

int cbm_trusted_root_read_file(const cbm_trusted_root_t *root, const char *rel_path,
                               size_t max_bytes, unsigned char **out_data, size_t *out_len,
                               struct stat *out_status) {
    if (!root || !trusted_rel_path_valid(rel_path) || !out_data || !out_len) {
        return CBM_NOT_FOUND;
    }
    *out_data = NULL;
    *out_len = 0;
    wchar_t *wide_rel = cbm_utf8_to_wide(rel_path);
    if (!wide_rel) {
        return CBM_NOT_FOUND;
    }
    /* GetFinalPathNameByHandleW returns an extended path (\\?\...), so using
     * the pinned root's final path also supports a short root plus a deep
     * Unicode relative path whose combined length exceeds MAX_PATH. */
    size_t root_len = wcslen(root->final_path);
    size_t rel_len = wcslen(wide_rel);
    if (root_len > SIZE_MAX - rel_len - 2) {
        free(wide_rel);
        return CBM_NOT_FOUND;
    }
    wchar_t *full = (wchar_t *)malloc((root_len + rel_len + 2) * sizeof(*full));
    if (!full) {
        free(wide_rel);
        return CBM_NOT_FOUND;
    }
    memcpy(full, root->final_path, root_len * sizeof(*full));
    full[root_len] = L'\\';
    memcpy(full + root_len + 1, wide_rel, (rel_len + 1) * sizeof(*full));
    free(wide_rel);

    /* Keep every relative ancestor pinned without write/delete sharing until
     * the read finishes. A final-path containment check alone is insufficient:
     * an in-root junction can redirect a tracked path to untracked in-root
     * content, and a checked ancestor can otherwise be replaced before the
     * final CreateFileW resolves it. */
    HANDLE *read_ancestor_handles = NULL;
    size_t read_ancestor_count = 0;
    if (!trusted_win_pin_ancestors(full, FILE_SHARE_READ, &read_ancestor_handles,
                                   &read_ancestor_count)) {
        free(full);
        return CBM_NOT_FOUND;
    }

    if (trusted_win_before_final_open_hook) {
        trusted_win_before_final_open_hook(trusted_win_before_final_open_context);
    }

    HANDLE file = CreateFileW(full, GENERIC_READ | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, trusted_win_final_open_flags(), NULL);
    free(full);
    if (file == INVALID_HANDLE_VALUE) {
        trusted_win_close_ancestors(read_ancestor_handles, read_ancestor_count);
        return CBM_NOT_FOUND;
    }
    FILE_ATTRIBUTE_TAG_INFO final_tag = {0};
    wchar_t *final_path = trusted_win_final_path(file);
    BY_HANDLE_FILE_INFORMATION before = {0};
    bool admitted =
        GetFileInformationByHandleEx(file, FileAttributeTagInfo, &final_tag, sizeof(final_tag)) &&
        !(final_tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) &&
        final_path && trusted_win_path_below(root->final_path, final_path) &&
        GetFileInformationByHandle(file, &before) &&
        !(before.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    free(final_path);
    uint64_t file_size = ((uint64_t)before.nFileSizeHigh << 32) | before.nFileSizeLow;
    size_t limit = max_bytes ? max_bytes : SIZE_MAX;
    if (!admitted || file_size > limit || file_size > SIZE_MAX - 1) {
        CloseHandle(file);
        trusted_win_close_ancestors(read_ancestor_handles, read_ancestor_count);
        return CBM_NOT_FOUND;
    }
    unsigned char *data = (unsigned char *)malloc((size_t)file_size + 1);
    if (!data) {
        CloseHandle(file);
        trusted_win_close_ancestors(read_ancestor_handles, read_ancestor_count);
        return CBM_NOT_FOUND;
    }
    size_t used = 0;
    bool read_ok = true;
    while (used < (size_t)file_size) {
        DWORD chunk = (DWORD)(((size_t)file_size - used) > UINT32_MAX ? UINT32_MAX
                                                                      : ((size_t)file_size - used));
        DWORD got = 0;
        if (!ReadFile(file, data + used, chunk, &got, NULL) || got == 0) {
            read_ok = false;
            break;
        }
        used += got;
    }
    BY_HANDLE_FILE_INFORMATION after = {0};
    read_ok = read_ok && GetFileInformationByHandle(file, &after) &&
              trusted_win_same_identity(&before, &after) &&
              before.nFileSizeHigh == after.nFileSizeHigh &&
              before.nFileSizeLow == after.nFileSizeLow &&
              before.ftLastWriteTime.dwHighDateTime == after.ftLastWriteTime.dwHighDateTime &&
              before.ftLastWriteTime.dwLowDateTime == after.ftLastWriteTime.dwLowDateTime;
    CloseHandle(file);
    trusted_win_close_ancestors(read_ancestor_handles, read_ancestor_count);
    if (!read_ok || used != (size_t)file_size) {
        free(data);
        return CBM_NOT_FOUND;
    }
    data[used] = '\0';
    if (out_status) {
        memset(out_status, 0, sizeof(*out_status));
        out_status->st_mode = S_IFREG;
        out_status->st_size = (off_t)used;
        out_status->st_mtime = trusted_win_filetime_seconds(after.ftLastWriteTime);
    }
    *out_data = data;
    *out_len = used;
    return 0;
}

#else

static int trusted_open_flags(int base) {
    int flags = base;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    return flags;
}

int cbm_trusted_root_open(const char *root_path, cbm_trusted_root_t **out) {
    if (!root_path || !out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    int fd = open(root_path, trusted_open_flags(O_RDONLY | O_DIRECTORY));
    if (fd < 0) {
        return CBM_NOT_FOUND;
    }
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode)) {
        close(fd);
        return CBM_NOT_FOUND;
    }
    cbm_trusted_root_t *root = (cbm_trusted_root_t *)calloc(1, sizeof(*root));
    if (!root) {
        close(fd);
        return CBM_NOT_FOUND;
    }
    root->fd = fd;
    root->device = status.st_dev;
    root->inode = status.st_ino;
    *out = root;
    return 0;
}

int cbm_trusted_root_open_mutable_ancestors(const char *root_path, cbm_trusted_root_t **out) {
    return cbm_trusted_root_open(root_path, out);
}

int cbm_trusted_root_upgrade_mutable_children(cbm_trusted_root_t *root, const char *root_path) {
    return cbm_trusted_root_matches_path(root, root_path) ? 0 : CBM_NOT_FOUND;
}

void cbm_trusted_root_close(cbm_trusted_root_t *root) {
    if (!root) {
        return;
    }
    if (root->fd >= 0) {
        close(root->fd);
    }
    free(root);
}

bool cbm_trusted_root_matches_path(const cbm_trusted_root_t *root, const char *path) {
    if (!root || !path) {
        return false;
    }
    int fd = open(path, trusted_open_flags(O_RDONLY | O_DIRECTORY));
    if (fd < 0) {
        return false;
    }
    struct stat status;
    bool matches = fstat(fd, &status) == 0 && S_ISDIR(status.st_mode) &&
                   status.st_dev == root->device && status.st_ino == root->inode;
    close(fd);
    return matches;
}

int cbm_trusted_root_dup_native_fd(const cbm_trusted_root_t *root) {
    if (!root) {
        return -1;
    }
#ifdef F_DUPFD_CLOEXEC
    return fcntl(root->fd, F_DUPFD_CLOEXEC, 0);
#else
    int duplicated = dup(root->fd);
    if (duplicated >= 0) {
        int flags = fcntl(duplicated, F_GETFD);
        if (flags < 0 || fcntl(duplicated, F_SETFD, flags | FD_CLOEXEC) != 0) {
            close(duplicated);
            return -1;
        }
    }
    return duplicated;
#endif
}

static int trusted_open_regular_at(const cbm_trusted_root_t *root, const char *rel_path) {
    if (!root || !trusted_rel_path_valid(rel_path)) {
        return -1;
    }
    int current = dup(root->fd);
    if (current < 0) {
        return -1;
    }
    const char *component = rel_path;
    for (;;) {
        const char *slash = strchr(component, '/');
        size_t len = slash ? (size_t)(slash - component) : strlen(component);
        char *name = (char *)malloc(len + 1);
        if (!name) {
            close(current);
            return -1;
        }
        memcpy(name, component, len);
        name[len] = '\0';
        int flags = slash ? (O_RDONLY | O_DIRECTORY) : O_RDONLY;
#ifdef O_NONBLOCK
        if (!slash) {
            /* A tracked pathname can be replaced by a FIFO between Git
             * enumeration and admission. Type-check it without blocking. */
            flags |= O_NONBLOCK;
        }
#endif
        int next = openat(current, name, trusted_open_flags(flags));
        free(name);
        close(current);
        if (next < 0) {
            return -1;
        }
        current = next;
        if (!slash) {
            break;
        }
        component = slash + 1;
    }
    struct stat status;
    if (fstat(current, &status) != 0 || !S_ISREG(status.st_mode)) {
        close(current);
        return -1;
    }
    return current;
}

static int64_t trusted_stat_change_ns(const struct stat *status) {
#ifdef __APPLE__
    return (int64_t)status->st_ctimespec.tv_sec * 1000000000LL + status->st_ctimespec.tv_nsec;
#else
    return (int64_t)status->st_ctim.tv_sec * 1000000000LL + status->st_ctim.tv_nsec;
#endif
}

static int64_t trusted_stat_modify_ns(const struct stat *status) {
#ifdef __APPLE__
    return (int64_t)status->st_mtimespec.tv_sec * 1000000000LL + status->st_mtimespec.tv_nsec;
#else
    return (int64_t)status->st_mtim.tv_sec * 1000000000LL + status->st_mtim.tv_nsec;
#endif
}

int cbm_trusted_root_read_file(const cbm_trusted_root_t *root, const char *rel_path,
                               size_t max_bytes, unsigned char **out_data, size_t *out_len,
                               struct stat *out_status) {
    if (!root || !out_data || !out_len) {
        return CBM_NOT_FOUND;
    }
    *out_data = NULL;
    *out_len = 0;
    int fd = trusted_open_regular_at(root, rel_path);
    if (fd < 0) {
        return CBM_NOT_FOUND;
    }
    struct stat before;
    if (fstat(fd, &before) != 0 || before.st_size < 0) {
        close(fd);
        return CBM_NOT_FOUND;
    }
    size_t limit = max_bytes ? max_bytes : SIZE_MAX;
    if ((uintmax_t)before.st_size > (uintmax_t)limit ||
        (uintmax_t)before.st_size > (uintmax_t)(SIZE_MAX - 1)) {
        close(fd);
        return CBM_NOT_FOUND;
    }
    size_t expected = (size_t)before.st_size;
    unsigned char *data = (unsigned char *)malloc(expected + 1);
    if (!data) {
        close(fd);
        return CBM_NOT_FOUND;
    }
    size_t used = 0;
    while (used < expected) {
        ssize_t got = read(fd, data + used, expected - used);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            free(data);
            close(fd);
            return CBM_NOT_FOUND;
        }
        used += (size_t)got;
    }
    unsigned char extra = 0;
    ssize_t extra_read;
    do {
        extra_read = read(fd, &extra, 1);
    } while (extra_read < 0 && errno == EINTR);
    struct stat after;
    bool stable = extra_read == 0 && fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
                  before.st_ino == after.st_ino && before.st_size == after.st_size &&
                  trusted_stat_modify_ns(&before) == trusted_stat_modify_ns(&after) &&
                  trusted_stat_change_ns(&before) == trusted_stat_change_ns(&after);
    close(fd);
    if (!stable) {
        free(data);
        return CBM_NOT_FOUND;
    }
    data[used] = '\0';
    if (out_status) {
        *out_status = after;
    }
    *out_data = data;
    *out_len = used;
    return 0;
}

#endif
