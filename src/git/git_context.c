#include "git/git_context.h"

#include "foundation/compat_fs.h"
#include "foundation/constants.h"
#include "foundation/platform.h"
#include "foundation/subprocess.h"
#include "foundation/str_util.h"
#include "foundation/trusted_fs.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include "foundation/win_utf8.h"
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

enum {
    GIT_CMD_MAX = 1024,
    GIT_OUTPUT_MAX = 4096,
    GIT_TRACKED_OUTPUT_MAX = 64 * 1024 * 1024,
    GIT_TRUSTED_TIMEOUT_MS = 60000,
};

static _Atomic uint64_t trusted_git_command_count;

void cbm_git_trusted_command_count_reset_for_tests(void) {
    atomic_store_explicit(&trusted_git_command_count, 0, memory_order_relaxed);
}

uint64_t cbm_git_trusted_command_count_for_tests(void) {
    return atomic_load_explicit(&trusted_git_command_count,
                                memory_order_relaxed);
}

static char *git_strdup(const char *s) {
    if (!s) {
        s = "";
    }
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (!out) {
        return NULL;
    }
    memcpy(out, s, n);
    return out;
}

static void trim_newlines(char *s) {
    if (!s) {
        return;
    }
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static bool git_validate_repo_path(const char *repo_path) {
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

static int git_capture(const char *repo_path, const char *git_args, char **out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    if (!repo_path || !git_args || !git_validate_repo_path(repo_path)) {
        return CBM_NOT_FOUND;
    }

    char cmd[GIT_CMD_MAX];
#ifdef _WIN32
    const char *null_dev = "NUL";
#else
    const char *null_dev = "/dev/null";
#endif
    /* Double quotes work for POSIX shells and cmd.exe. cbm_validate_shell_arg()
     * rejects quote/backslash/substitution metacharacters before interpolation. */
    int n = snprintf(cmd, sizeof(cmd), "git -C \"%s\" %s 2>%s", repo_path, git_args, null_dev);
    if (n < 0 || n >= (int)sizeof(cmd)) {
        return CBM_NOT_FOUND;
    }

    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
        return CBM_NOT_FOUND;
    }

    char buf[GIT_OUTPUT_MAX];
    if (!fgets(buf, sizeof(buf), fp)) {
        cbm_pclose(fp);
        return CBM_NOT_FOUND;
    }
    trim_newlines(buf);

    int rc = cbm_pclose(fp);
    if (rc != 0 || buf[0] == '\0') {
        return CBM_NOT_FOUND;
    }

    *out = git_strdup(buf);
    return *out ? 0 : CBM_NOT_FOUND;
}

typedef struct {
    char *executable;
    const char *repo_path;
    const cbm_trusted_root_t *root;
#ifndef _WIN32
    int repo_fd;
#endif
} trusted_git_session_t;

static char *trusted_git_executable(void) {
#ifdef _WIN32
    static const wchar_t *const candidates[] = {
        L"C:\\Program Files\\Git\\cmd\\git.exe",
        L"C:\\Program Files\\Git\\bin\\git.exe",
        L"C:\\Program Files (x86)\\Git\\cmd\\git.exe",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        DWORD attributes = GetFileAttributesW(candidates[i]);
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            return cbm_wide_to_utf8(candidates[i]);
        }
    }
    return NULL;
#else
    static const char *const candidates[] = {
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        struct stat status;
        if (lstat(candidates[i], &status) != 0 ||
            (!S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode)) ||
            access(candidates[i], X_OK) != 0) {
            continue;
        }
        char resolved[PATH_MAX];
        if (!realpath(candidates[i], resolved) || stat(resolved, &status) != 0 ||
            !S_ISREG(status.st_mode) || access(resolved, X_OK) != 0) {
            continue;
        }
        return git_strdup(resolved);
    }
    return NULL;
#endif
}

static bool trusted_git_session_open(const char *repo_path, const cbm_trusted_root_t *root,
                                     trusted_git_session_t *session) {
    if (!repo_path || !root || !session ||
        !cbm_trusted_root_matches_path(root, repo_path)) {
        return false;
    }
    memset(session, 0, sizeof(*session));
#ifndef _WIN32
    session->repo_fd = -1;
#endif
    session->executable = trusted_git_executable();
    session->repo_path = repo_path;
    session->root = root;
    if (!session->executable) {
        return false;
    }
#ifndef _WIN32
    session->repo_fd = cbm_trusted_root_dup_native_fd(root);
    if (session->repo_fd < 0) {
        free(session->executable);
        session->executable = NULL;
        return false;
    }
#endif
    return true;
}

static void trusted_git_session_close(trusted_git_session_t *session) {
    if (!session) {
        return;
    }
#ifndef _WIN32
    if (session->repo_fd >= 0) {
        close(session->repo_fd);
    }
#endif
    free(session->executable);
    memset(session, 0, sizeof(*session));
}

static bool trusted_git_grow_output(unsigned char **raw, size_t *capacity, size_t needed,
                                    size_t limit) {
    if (!raw || !capacity || needed > limit) {
        return false;
    }
    if (needed <= *capacity) {
        return true;
    }
    size_t grown = *capacity ? *capacity : CBM_SZ_8K;
    while (grown < needed) {
        grown = grown > limit / PAIR_LEN ? limit : grown * PAIR_LEN;
    }
    unsigned char *next = (unsigned char *)realloc(*raw, grown);
    if (!next) {
        return false;
    }
    *raw = next;
    *capacity = grown;
    return true;
}

#ifndef _WIN32
static uint64_t trusted_git_monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void trusted_git_kill_process_group(pid_t child) {
    if (child <= 0) {
        return;
    }
    /*
     * The child creates a dedicated group before exec. Kill both the group
     * and the leader: the latter covers the narrow setpgid race/failure path.
     */
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
}

static bool trusted_git_pipe_cloexec(int pipe_fds[2]) {
#ifdef __linux__
    if (pipe2(pipe_fds, O_CLOEXEC) == 0) {
        return true;
    }
    if (errno != ENOSYS && errno != EINVAL) {
        return false;
    }
#endif
    if (pipe(pipe_fds) != 0) {
        return false;
    }
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(pipe_fds[i], F_GETFD);
        if (flags < 0 ||
            fcntl(pipe_fds[i], F_SETFD, flags | FD_CLOEXEC) != 0) {
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return false;
        }
    }
    return true;
}
#endif

static int trusted_git_run(const trusted_git_session_t *session,
                           const char *const *git_args, size_t output_limit,
                           unsigned char **out, size_t *out_len) {
    if (!session || !session->executable || !git_args || !out || !out_len ||
        output_limit == 0) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    *out_len = 0;
    const char *argv[32];
    int argc = 0;
    argv[argc++] = session->executable;
    argv[argc++] = "--no-pager";
    argv[argc++] = "-c";
    argv[argc++] = "core.fsmonitor=false";
    argv[argc++] = "-c";
    argv[argc++] = "core.untrackedCache=false";
    int arg_index = 0;
    for (; git_args[arg_index] &&
           argc < (int)(sizeof(argv) / sizeof(argv[0])) - 1;
         arg_index++) {
        argv[argc++] = git_args[arg_index];
    }
    argv[argc] = NULL;
    if (git_args[arg_index] != NULL ||
        !cbm_trusted_root_matches_path(session->root, session->repo_path)) {
        return CBM_NOT_FOUND;
    }
    atomic_fetch_add_explicit(&trusted_git_command_count, 1,
                              memory_order_relaxed);

    unsigned char *raw = NULL;
    size_t raw_len = 0;
    size_t raw_capacity = 0;
    bool failed = false;
#ifdef _WIN32
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security),
        .lpSecurityDescriptor = NULL,
        .bInheritHandle = TRUE,
    };
    HANDLE read_pipe = NULL;
    HANDLE write_pipe = NULL;
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0) ||
        !SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0)) {
        if (read_pipe) {
            CloseHandle(read_pipe);
        }
        if (write_pipe) {
            CloseHandle(write_pipe);
        }
        return CBM_NOT_FOUND;
    }
    HANDLE null_handle =
        CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (null_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        return CBM_NOT_FOUND;
    }
    char command_line[CBM_SZ_4K];
    if (!cbm_build_win_cmdline(command_line, sizeof(command_line), argv)) {
        CloseHandle(null_handle);
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        return CBM_NOT_FOUND;
    }
    wchar_t *wide_executable = cbm_utf8_to_wide(session->executable);
    wchar_t *wide_command = cbm_utf8_to_wide(command_line);
    wchar_t *wide_repo = cbm_path_to_wide(session->repo_path);
    wchar_t environment[] =
        L"GIT_CONFIG_GLOBAL=NUL\0"
        L"GIT_CONFIG_NOSYSTEM=1\0"
        L"GIT_NO_LAZY_FETCH=1\0"
        L"GIT_NO_REPLACE_OBJECTS=1\0"
        L"GIT_OPTIONAL_LOCKS=0\0"
        L"GIT_PAGER=cat\0"
        L"GIT_TERMINAL_PROMPT=0\0"
        L"LANG=C\0"
        L"LC_ALL=C\0"
        L"PATH=\0\0";
    HANDLE inherit[] = {write_pipe, null_handle};
    SIZE_T attribute_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0,
                                            &attribute_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attributes =
        (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attribute_size);
    bool attributes_initialized =
        attributes &&
        InitializeProcThreadAttributeList(attributes, 1, 0,
                                          &attribute_size);
    bool attributes_ready =
        attributes_initialized &&
        UpdateProcThreadAttribute(attributes, 0,
                                  PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                  sizeof(inherit), NULL, NULL);
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_handle;
    startup.StartupInfo.hStdOutput = write_pipe;
    startup.StartupInfo.hStdError = null_handle;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process = {0};
    BOOL created =
        wide_executable && wide_command && wide_repo && attributes_ready &&
        CreateProcessW(wide_executable, wide_command, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
                           EXTENDED_STARTUPINFO_PRESENT,
                       environment, wide_repo, &startup.StartupInfo, &process);
    if (attributes_initialized) {
        DeleteProcThreadAttributeList(attributes);
    }
    free(attributes);
    free(wide_executable);
    free(wide_command);
    free(wide_repo);
    CloseHandle(write_pipe);
    CloseHandle(null_handle);
    if (!created) {
        CloseHandle(read_pipe);
        return CBM_NOT_FOUND;
    }
    unsigned char chunk[CBM_SZ_8K];
    ULONGLONG deadline = GetTickCount64() + GIT_TRUSTED_TIMEOUT_MS;
    bool process_done = false;
    for (;;) {
        bool peek_after_exit = process_done;
        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL)) {
            DWORD error = GetLastError();
            if (error != ERROR_BROKEN_PIPE) {
                failed = true;
            }
            break;
        }
        while (available > 0) {
            DWORD request = available > sizeof(chunk) ? sizeof(chunk) : available;
            DWORD got = 0;
            if (!ReadFile(read_pipe, chunk, request, &got, NULL) || got == 0) {
                failed = true;
                available = 0;
                break;
            }
            if (!failed) {
                size_t needed = raw_len + (size_t)got;
                if (needed < raw_len ||
                    !trusted_git_grow_output(&raw, &raw_capacity, needed,
                                             output_limit)) {
                    failed = true;
                } else {
                    memcpy(raw + raw_len, chunk, got);
                    raw_len = needed;
                }
            }
            available -= got;
        }
        /*
         * wait below may discover exit after this peek. Only a peek performed
         * on a later iteration is allowed to prove the pipe drained; otherwise
         * final bytes written immediately before exit can be truncated.
         */
        if (peek_after_exit && available == 0) {
            break;
        }
        DWORD wait = WaitForSingleObject(process.hProcess, 0);
        if (wait == WAIT_OBJECT_0) {
            process_done = true;
        } else if (wait == WAIT_FAILED) {
            failed = true;
            break;
        }
        if (failed && !process_done) {
            (void)TerminateProcess(process.hProcess, 124);
            (void)WaitForSingleObject(process.hProcess, 5000);
            process_done = true;
        }
        if (!process_done && GetTickCount64() >= deadline) {
            (void)TerminateProcess(process.hProcess, 124);
            (void)WaitForSingleObject(process.hProcess, 5000);
            failed = true;
            process_done = true;
        }
        Sleep(1);
    }
    CloseHandle(read_pipe);
    if (!process_done) {
        DWORD waited =
            WaitForSingleObject(process.hProcess, GIT_TRUSTED_TIMEOUT_MS);
        if (waited != WAIT_OBJECT_0) {
            (void)TerminateProcess(process.hProcess, 124);
            (void)WaitForSingleObject(process.hProcess, 5000);
            failed = true;
        }
    }
    DWORD exit_code = 1;
    (void)GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    failed = failed || exit_code != 0;
#else
    int pipe_fds[2];
    if (!trusted_git_pipe_cloexec(pipe_fds)) {
        return CBM_NOT_FOUND;
    }
    pid_t child = fork();
    if (child == 0) {
        if (setpgid(0, 0) != 0) {
            _exit(126);
        }
        int null_fd = open("/dev/null", O_WRONLY);
        if (fchdir(session->repo_fd) != 0 || dup2(pipe_fds[1], STDOUT_FILENO) < 0 ||
            null_fd < 0 || dup2(null_fd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        close(null_fd);
        close(session->repo_fd);
        static char *const environment[] = {
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_NO_LAZY_FETCH=1",
            "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_OPTIONAL_LOCKS=0",
            "GIT_PAGER=cat",
            "GIT_TERMINAL_PROMPT=0",
            "LANG=C",
            "LC_ALL=C",
            "PATH=/usr/bin:/bin",
            NULL,
        };
        execve(session->executable, (char *const *)argv, environment);
        _exit(127);
    }
    close(pipe_fds[1]);
    if (child < 0) {
        close(pipe_fds[0]);
        return CBM_NOT_FOUND;
    }
    /*
     * Close the fork/exec race from the parent too. EACCES means the child
     * already exec'd after successfully creating its own group.
     */
    if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
        trusted_git_kill_process_group(child);
        close(pipe_fds[0]);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
        }
        return CBM_NOT_FOUND;
    }
    int pipe_flags = fcntl(pipe_fds[0], F_GETFL, 0);
    if (pipe_flags < 0 ||
        fcntl(pipe_fds[0], F_SETFL, pipe_flags | O_NONBLOCK) != 0) {
        trusted_git_kill_process_group(child);
        close(pipe_fds[0]);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
        }
        return CBM_NOT_FOUND;
    }
    unsigned char chunk[CBM_SZ_8K];
    uint64_t started = trusted_git_monotonic_ms();
    uint64_t deadline =
        started > UINT64_MAX - GIT_TRUSTED_TIMEOUT_MS
            ? UINT64_MAX
            : started + GIT_TRUSTED_TIMEOUT_MS;
    bool child_done = false;
    bool group_killed = false;
    int status = 0;
    for (;;) {
        for (;;) {
            ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));
            if (got > 0) {
                if (!failed) {
                    size_t needed = raw_len + (size_t)got;
                    if (needed < raw_len ||
                        !trusted_git_grow_output(&raw, &raw_capacity, needed,
                                                 output_limit)) {
                        failed = true;
                    } else {
                        memcpy(raw + raw_len, chunk, (size_t)got);
                        raw_len = needed;
                    }
                }
                continue;
            }
            if (got == 0) {
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                if (errno != EINTR) {
                    failed = true;
                } else {
                    continue;
                }
            }
            break;
        }
        if (!child_done) {
            pid_t waited;
            do {
                waited = waitpid(child, &status, WNOHANG);
            } while (waited < 0 && errno == EINTR);
            if (waited == child) {
                child_done = true;
            } else if (waited < 0) {
                failed = true;
                child_done = true;
            }
        }
        if (child_done) {
            /*
             * Once waitpid observes leader exit, every byte written by that
             * leader is already in the pipe. Terminate ordinary descendants,
             * perform one final nonblocking drain, then close our read end.
             * Never wait for EOF: an adversarial helper can setsid() and retain
             * stdout outside the process group indefinitely.
             */
            if (!group_killed) {
                (void)kill(-child, SIGKILL);
                group_killed = true;
            }
            for (;;) {
                ssize_t got = read(pipe_fds[0], chunk, sizeof(chunk));
                if (got > 0) {
                    if (!failed) {
                        size_t needed = raw_len + (size_t)got;
                        if (needed < raw_len ||
                            !trusted_git_grow_output(&raw, &raw_capacity,
                                                     needed, output_limit)) {
                            failed = true;
                        } else {
                            memcpy(raw + raw_len, chunk, (size_t)got);
                            raw_len = needed;
                        }
                    }
                    continue;
                }
                if (got < 0 && errno == EINTR) {
                    continue;
                }
                if (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    failed = true;
                }
                break;
            }
            break;
        }
        if (failed && !group_killed) {
            trusted_git_kill_process_group(child);
            group_killed = true;
        }
        uint64_t now = trusted_git_monotonic_ms();
        if (started == 0 || now == 0 || now >= deadline) {
            failed = true;
            if (!group_killed) {
                trusted_git_kill_process_group(child);
                group_killed = true;
            }
        }
        int timeout_ms = 10;
        if (!group_killed && now < deadline) {
            uint64_t remaining = deadline - now;
            timeout_ms = remaining < 50u ? (int)remaining : 50;
        }
        struct pollfd watched = {
            .fd = pipe_fds[0],
            .events = POLLIN | POLLHUP,
            .revents = 0,
        };
        int polled;
        do {
            polled = poll(&watched, 1, timeout_ms);
        } while (polled < 0 && errno == EINTR);
        if (polled < 0) {
            failed = true;
            if (!group_killed) {
                trusted_git_kill_process_group(child);
                group_killed = true;
            }
        }
    }
    close(pipe_fds[0]);
    if (!child_done) {
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
    }
    failed = failed || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
#endif
    if (failed) {
        free(raw);
        return CBM_NOT_FOUND;
    }
    *out = raw;
    *out_len = raw_len;
    return 0;
}

static int trusted_git_capture(const trusted_git_session_t *session,
                               const char *const *args, char **out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    if (trusted_git_run(session, args, GIT_OUTPUT_MAX - 1, &raw, &raw_len) != 0 ||
        raw_len == 0 || memchr(raw, '\0', raw_len) != NULL) {
        free(raw);
        return CBM_NOT_FOUND;
    }
    char *text = (char *)realloc(raw, raw_len + 1);
    if (!text) {
        free(raw);
        return CBM_NOT_FOUND;
    }
    text[raw_len] = '\0';
    trim_newlines(text);
    if (!text[0]) {
        free(text);
        return CBM_NOT_FOUND;
    }
    *out = text;
    return 0;
}

static char *trusted_git_dup_line(char *start, char *end) {
    if (!start || !end || end < start) {
        return NULL;
    }
    if (end > start && end[-1] == '\r') {
        end--;
    }
    size_t len = (size_t)(end - start);
    if (len == 0) {
        return NULL;
    }
    char *line = (char *)malloc(len + 1);
    if (line) {
        memcpy(line, start, len);
        line[len] = '\0';
    }
    return line;
}

/* Parse the four-line trusted rev-parse batch. Newlines in a repository path
 * make the framing ambiguous and therefore fail closed. */
static bool trusted_git_parse_context_batch(char *text, char **worktree,
                                            char **git_dir, char **common_dir,
                                            char **head_sha) {
    if (!text || !worktree || !git_dir || !common_dir || !head_sha) {
        return false;
    }
    *worktree = NULL;
    *git_dir = NULL;
    *common_dir = NULL;
    *head_sha = NULL;
    char *starts[4] = {text, NULL, NULL, NULL};
    char *ends[4] = {NULL, NULL, NULL, NULL};
    char *cursor = text;
    for (int i = 0; i < 3; i++) {
        char *newline = strchr(cursor, '\n');
        if (!newline) {
            return false;
        }
        ends[i] = newline;
        starts[i + 1] = newline + 1;
        cursor = newline + 1;
    }
    if (strchr(cursor, '\n') != NULL) {
        return false;
    }
    ends[3] = cursor + strlen(cursor);
    char **outputs[] = {worktree, git_dir, common_dir, head_sha};
    for (int i = 0; i < 4; i++) {
        *outputs[i] = trusted_git_dup_line(starts[i], ends[i]);
        if (!*outputs[i]) {
            for (int j = 0; j <= i; j++) {
                free(*outputs[j]);
                *outputs[j] = NULL;
            }
            return false;
        }
    }
    return true;
}

static int git_path_cmp(const void *lhs, const void *rhs) {
    const char *const *a = (const char *const *)lhs;
    const char *const *b = (const char *const *)rhs;
    return strcmp(*a, *b);
}

void cbm_git_free_tracked_files(char **files, int count) {
    if (!files) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(files[i]);
    }
    free(files);
}

static int git_parse_tracked_output(const unsigned char *raw, size_t raw_len,
                                    char ***out, int *count) {
    if (!out || !count || (raw_len > 0 && !raw) ||
        (raw_len > 0 && raw[raw_len - 1] != '\0')) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    *count = 0;
    if (raw_len == 0) {
        return 0;
    }
    int path_count = 0;
    for (size_t i = 0; i < raw_len; i++) {
        if (raw[i] == '\0') {
            if (path_count == INT_MAX) {
                return CBM_NOT_FOUND;
            }
            path_count++;
        }
    }
    char **paths = (char **)calloc((size_t)path_count, sizeof(*paths));
    if (!paths) {
        return CBM_NOT_FOUND;
    }
    int path_index = 0;
    size_t start = 0;
    for (size_t i = 0; i < raw_len; i++) {
        if (raw[i] != '\0') {
            continue;
        }
        size_t path_len = i - start;
        if (path_len == 0 || path_len >= CBM_SZ_4K) {
            cbm_git_free_tracked_files(paths, path_index);
            return CBM_NOT_FOUND;
        }
        paths[path_index] = (char *)malloc(path_len + 1);
        if (!paths[path_index]) {
            cbm_git_free_tracked_files(paths, path_index);
            return CBM_NOT_FOUND;
        }
        memcpy(paths[path_index], raw + start, path_len);
        paths[path_index][path_len] = '\0';
#ifdef _WIN32
        cbm_normalize_path_sep(paths[path_index]);
#endif
        path_index++;
        start = i + 1;
    }
    qsort(paths, (size_t)path_index, sizeof(*paths), git_path_cmp);
    int unique_count = 0;
    for (int i = 0; i < path_index; i++) {
        if (unique_count > 0 && strcmp(paths[unique_count - 1], paths[i]) == 0) {
            free(paths[i]);
        } else {
            paths[unique_count++] = paths[i];
        }
    }
    *out = paths;
    *count = unique_count;
    return 0;
}

int cbm_git_list_tracked_files(const char *repo_path, char ***out, int *count) {
    if (!out || !count) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    *count = 0;
    if (!repo_path || !git_validate_repo_path(repo_path)) {
        return CBM_NOT_FOUND;
    }

    char cmd[GIT_CMD_MAX];
#ifdef _WIN32
    const char *null_dev = "NUL";
#else
    const char *null_dev = "/dev/null";
#endif
    int n = snprintf(cmd, sizeof(cmd), "git -C \"%s\" ls-files -z 2>%s", repo_path, null_dev);
    if (n < 0 || n >= (int)sizeof(cmd)) {
        return CBM_NOT_FOUND;
    }

    FILE *fp = cbm_popen(cmd, "r");
    if (!fp) {
        return CBM_NOT_FOUND;
    }

    unsigned char chunk[CBM_SZ_8K];
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    size_t raw_cap = 0;
    bool failed = false;
    for (;;) {
        size_t got = fread(chunk, 1, sizeof(chunk), fp);
        if (got > 0) {
            if (!failed) {
                if (raw_len > (size_t)GIT_TRACKED_OUTPUT_MAX - got) {
                    failed = true;
                } else {
                    size_t needed = raw_len + got;
                    if (needed > raw_cap) {
                        size_t grown_cap = raw_cap ? raw_cap : sizeof(chunk);
                        while (grown_cap < needed) {
                            grown_cap =
                                grown_cap > (size_t)GIT_TRACKED_OUTPUT_MAX / 2
                                    ? (size_t)GIT_TRACKED_OUTPUT_MAX
                                    : grown_cap * 2;
                        }
                        unsigned char *grown = (unsigned char *)realloc(raw, grown_cap);
                        if (!grown) {
                            failed = true;
                        } else {
                            raw = grown;
                            raw_cap = grown_cap;
                        }
                    }
                    if (!failed) {
                        memcpy(raw + raw_len, chunk, got);
                        raw_len = needed;
                    }
                }
            }
        }
        if (got < sizeof(chunk)) {
            if (ferror(fp)) {
                failed = true;
            }
            break;
        }
    }

    int close_rc = cbm_pclose(fp);
    int rc = !failed && close_rc == 0
                 ? git_parse_tracked_output(raw, raw_len, out, count)
                 : CBM_NOT_FOUND;
    free(raw);
    return rc;
}

int cbm_git_list_tracked_files_trusted(const char *repo_path,
                                       const cbm_trusted_root_t *root, char ***out,
                                       int *count) {
    if (!out || !count) {
        return CBM_NOT_FOUND;
    }
    *out = NULL;
    *count = 0;
    trusted_git_session_t session;
    if (!trusted_git_session_open(repo_path, root, &session)) {
        return CBM_NOT_FOUND;
    }
    static const char *const args[] = {"ls-files", "-z", NULL};
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    int rc = trusted_git_run(&session, args, GIT_TRACKED_OUTPUT_MAX, &raw, &raw_len);
    if (rc == 0) {
        rc = git_parse_tracked_output(raw, raw_len, out, count);
    }
    free(raw);
    trusted_git_session_close(&session);
    return rc;
}

static bool path_is_absolute(const char *path) {
    if (!path || !path[0]) {
        return false;
    }
    if (path[0] == '/') {
        return true;
    }
#ifdef _WIN32
    return isalpha((unsigned char)path[0]) && path[1] == ':';
#else
    return false;
#endif
}

static char *join_root_relative(const char *root, const char *rel) {
    if (!root || !root[0]) {
        return git_strdup(rel);
    }
    int n = snprintf(NULL, 0, "%s/%s", root, rel);
    if (n < 0) {
        return NULL;
    }
    char *out = (char *)malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }
    snprintf(out, (size_t)n + 1, "%s/%s", root, rel);
    return out;
}

/* Derive the canonical repo root.
 *
 * Preferred (git 2.31+): abs_common_dir is `git rev-parse --path-format=absolute
 * --git-common-dir` — git's OWN absolute, canonical common-dir. Because a main
 * repo and its linked worktree both ask the same git binary, they resolve to the
 * IDENTICAL path, so canonical_root is consistent across worktrees AND platforms
 * with no manual join or realpath/_fullpath — which diverged under msys vs native
 * path representations (#659 root cause, and the worktree==main-root breakage in
 * test_pipeline.c git_context_linked_worktree). git also resolves the relative
 * ".." internally, so the subdirectory case (#659) is fixed here too.
 *
 * Fallback (git < 2.31, no --path-format → abs_common_dir empty): the relative
 * --git-common-dir is relative to input_path (the -C dir), so join against it and
 * realpath-normalize the "..". Unix only — on Windows git emits an absolute
 * common-dir so this branch isn't reached in practice, and _fullpath there
 * reintroduces the msys divergence. */
static char *derive_canonical_root(const char *input_path, const char *worktree_root,
                                   const char *git_common_dir, const char *abs_common_dir) {
    char *root = NULL;
    if (abs_common_dir && abs_common_dir[0] && path_is_absolute(abs_common_dir)) {
        root = git_strdup(abs_common_dir);
        if (!root) {
            return NULL;
        }
    } else {
        const char *src = git_common_dir && git_common_dir[0] ? git_common_dir : worktree_root;
        if (!src) {
            return git_strdup("");
        }
#ifndef _WIN32
        root = path_is_absolute(src) ? git_strdup(src) : join_root_relative(input_path, src);
        if (!root) {
            return NULL;
        }
        {
            char resolved[4096];
            if (realpath(root, resolved) != NULL) {
                free(root);
                root = git_strdup(resolved);
                if (!root) {
                    return NULL;
                }
            }
        }
#else
        (void)input_path;
        root = path_is_absolute(src) ? git_strdup(src) : join_root_relative(worktree_root, src);
        if (!root) {
            return NULL;
        }
#endif
    }

    size_t len = strlen(root);
    while (len > 1 && (root[len - 1] == '/' || root[len - 1] == '\\')) {
        root[--len] = '\0';
    }

    if (len >= 5 && strcmp(root + len - 5, "/.git") == 0) {
        root[len - 5] = '\0';
    }
#ifdef _WIN32
    else if (len >= 5 && strcmp(root + len - 5, "\\.git") == 0) {
        root[len - 5] = '\0';
    }
#endif

    return root;
}

static char *slug_from_branch(const char *branch, bool detached) {
    const char *fallback = detached ? "detached" : "working-tree";
    const char *src = detached ? fallback : (branch && branch[0] ? branch : fallback);
    size_t len = strlen(src);
    char *slug = (char *)malloc(len + 1);
    if (!slug) {
        return NULL;
    }

    size_t j = 0;
    bool in_dash = false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.') {
            if (j == 0 && c == '-') {
                in_dash = true;
                continue;
            }
            slug[j++] = (char)c;
            in_dash = false;
        } else if (j > 0 && !in_dash) {
            slug[j++] = '-';
            in_dash = true;
        }
    }
    while (j > 0 && slug[j - 1] == '-') {
        j--;
    }
    slug[j] = '\0';

    if (slug[0] == '\0') {
        free(slug);
        return git_strdup(fallback);
    }
    return slug;
}

void cbm_git_context_free(cbm_git_context_t *ctx) {
    if (!ctx) {
        return;
    }
    free(ctx->input_path);
    free(ctx->worktree_root);
    free(ctx->git_dir);
    free(ctx->git_common_dir);
    free(ctx->canonical_root);
    free(ctx->branch);
    free(ctx->branch_slug);
    free(ctx->head_sha);
    free(ctx->base_sha);
    memset(ctx, 0, sizeof(*ctx));
}

int cbm_git_context_resolve(const char *path, cbm_git_context_t *out) {
    if (!out) {
        return CBM_NOT_FOUND;
    }

    memset(out, 0, sizeof(*out));
    if (!path || !path[0]) {
        return CBM_NOT_FOUND;
    }

    out->input_path = git_strdup(path);
    if (!out->input_path) {
        return CBM_NOT_FOUND;
    }

    struct stat st;
    out->root_exists = (stat(path, &st) == 0);
    if (!out->root_exists) {
        return 0;
    }

    if (git_capture(path, "rev-parse --show-toplevel", &out->worktree_root) != 0) {
        out->is_git = false;
        return 0;
    }
    out->is_git = true;

    if (git_capture(path, "rev-parse --git-dir", &out->git_dir) != 0) {
        out->git_dir = git_strdup("");
    }
    if (git_capture(path, "rev-parse --git-common-dir", &out->git_common_dir) != 0) {
        out->git_common_dir = git_strdup("");
    }
    if (git_capture(path, "rev-parse --verify HEAD", &out->head_sha) != 0) {
        out->head_sha = git_strdup("");
    }

    if (git_capture(path, "symbolic-ref --quiet --short HEAD", &out->branch) != 0) {
        out->branch = git_strdup("DETACHED");
        out->is_detached = true;
    }

    out->is_worktree =
        out->git_dir && out->git_common_dir && strcmp(out->git_dir, out->git_common_dir) != 0;
    /* git 2.31+ canonical absolute common-dir (best-effort; NULL on older git,
     * where derive_canonical_root falls back to the relative common-dir). */
    char *abs_common_dir = NULL;
    (void)git_capture(path, "rev-parse --path-format=absolute --git-common-dir", &abs_common_dir);
    out->canonical_root =
        derive_canonical_root(path, out->worktree_root, out->git_common_dir, abs_common_dir);
    free(abs_common_dir);
    out->branch_slug = slug_from_branch(out->branch, out->is_detached);
    if (git_capture(path, "merge-base HEAD @{upstream}", &out->base_sha) != 0) {
        out->base_sha = git_strdup("");
    }

    if (!out->git_dir || !out->git_common_dir || !out->head_sha || !out->branch ||
        !out->canonical_root || !out->branch_slug || !out->base_sha) {
        cbm_git_context_free(out);
        return CBM_NOT_FOUND;
    }

    return 0;
}

int cbm_git_context_resolve_trusted(const char *path, const cbm_trusted_root_t *root,
                                    cbm_git_context_t *out) {
    if (!path || !root || !out) {
        return CBM_NOT_FOUND;
    }
    memset(out, 0, sizeof(*out));
    out->input_path = git_strdup(path);
    out->root_exists = cbm_trusted_root_matches_path(root, path);
    if (!out->input_path || !out->root_exists) {
        cbm_git_context_free(out);
        return CBM_NOT_FOUND;
    }
    trusted_git_session_t session;
    if (!trusted_git_session_open(path, root, &session)) {
        cbm_git_context_free(out);
        return CBM_NOT_FOUND;
    }
    static const char *const context_batch[] = {
        "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir",
        "--git-common-dir", "--verify", "HEAD", NULL,
    };
    static const char *const branch[] = {
        "symbolic-ref", "--quiet", "--short", "HEAD", NULL,
    };
    static const char *const merge_base[] = {
        "merge-base", "HEAD", "@{upstream}", NULL,
    };
    char *batched = NULL;
    int batch_rc = trusted_git_capture(&session, context_batch, &batched);
    bool batched_ok = batch_rc == 0 &&
                      trusted_git_parse_context_batch(
                          batched, &out->worktree_root, &out->git_dir,
                          &out->git_common_dir, &out->head_sha);
    free(batched);
    if (batch_rc == 0 && !batched_ok) {
        /* The modern command succeeded but its newline framing was ambiguous
         * (for example a repository path contains a newline). Falling back to
         * individually line-trimmed commands would silently accept precisely
         * the input the trusted framing rejected. */
        cbm_git_context_free(out);
        trusted_git_session_close(&session);
        return CBM_NOT_FOUND;
    }
    if (!batched_ok) {
        /* Trusted snapshots require the absolute, atomically framed command.
         * Any command failure (including an output cap) must fail closed rather
         * than silently switching to weaker path semantics. */
        cbm_git_context_free(out);
        trusted_git_session_close(&session);
        return CBM_NOT_FOUND;
    }
    /* Strict snapshots are rooted at the selected worktree, not an arbitrary
     * subdirectory. This binds Git's relative manifest to the same directory
     * handle used for source reads. */
    if (!cbm_trusted_root_matches_path(root, out->worktree_root)) {
        trusted_git_session_close(&session);
        cbm_git_context_free(out);
        return CBM_NOT_FOUND;
    }
    out->is_git = true;
    if (trusted_git_capture(&session, branch, &out->branch) != 0) {
        out->branch = git_strdup("DETACHED");
        out->is_detached = true;
    }
    out->is_worktree =
        out->git_dir && out->git_common_dir &&
        strcmp(out->git_dir, out->git_common_dir) != 0;
    char *absolute_common = git_strdup(out->git_common_dir);
    out->canonical_root =
        derive_canonical_root(path, out->worktree_root, out->git_common_dir, absolute_common);
    free(absolute_common);
    out->branch_slug = slug_from_branch(out->branch, out->is_detached);
    if (trusted_git_capture(&session, merge_base, &out->base_sha) != 0) {
        out->base_sha = git_strdup("");
    }
    trusted_git_session_close(&session);
    if (!out->git_dir || !out->git_common_dir || !out->head_sha || !out->branch ||
        !out->canonical_root || !out->branch_slug || !out->base_sha ||
        !cbm_trusted_root_matches_path(root, path)) {
        cbm_git_context_free(out);
        return CBM_NOT_FOUND;
    }
    return 0;
}

char *cbm_git_context_branch_qn(const char *project_name, const cbm_git_context_t *ctx) {
    const char *project = project_name && project_name[0] ? project_name : "project";
    const char *slug = "working-tree";
    if (ctx) {
        if (ctx->is_detached) {
            slug = "detached";
        } else if (ctx->is_git && ctx->branch_slug && ctx->branch_slug[0]) {
            slug = ctx->branch_slug;
        }
    }

    int n = snprintf(NULL, 0, "%s.__branch__.%s", project, slug);
    if (n < 0) {
        return NULL;
    }
    char *out = (char *)malloc((size_t)n + 1);
    if (!out) {
        return NULL;
    }
    snprintf(out, (size_t)n + 1, "%s.__branch__.%s", project, slug);
    return out;
}

static bool append_fmt_checked(char *buf, int buf_size, int *off, const char *fmt, ...) {
    if (!buf || !off || buf_size <= 0 || *off < 0 || *off >= buf_size) {
        return false;
    }

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, (size_t)(buf_size - *off), fmt, ap);
    va_end(ap);
    if (n < 0 || n >= buf_size - *off) {
        buf[buf_size - 1] = '\0';
        return false;
    }
    *off += n;
    return true;
}

static int json_escaped_len(const char *src) {
    if (!src) {
        return 0;
    }
    int len = 0;
    for (int i = 0; src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') {
            len += 2;
        } else if (c < 0x20) {
            len += 6; /* \u00XX */
        } else {
            len++;
        }
    }
    return len;
}

static bool json_append_bool(char *buf, int buf_size, int *off, const char *name, bool value,
                             bool comma) {
    return append_fmt_checked(buf, buf_size, off, "\"%s\":%s%s", name, value ? "true" : "false",
                              comma ? "," : "");
}

static bool json_append_string(char *buf, int buf_size, int *off, const char *name,
                               const char *value, bool comma) {
    int needed = json_escaped_len(value ? value : "");
    char *escaped = malloc((size_t)needed + 1);
    if (!escaped) {
        return false;
    }
    int actual = cbm_json_escape(escaped, needed + 1, value ? value : "");
    bool ok = actual == needed && append_fmt_checked(buf, buf_size, off, "\"%s\":\"%s\"%s", name,
                                                     escaped, comma ? "," : "");
    free(escaped);
    return ok;
}

int cbm_git_context_props_json(const cbm_git_context_t *ctx, char *buf, int buf_size) {
    if (!ctx || !buf || buf_size <= 0) {
        return 0;
    }

    int off = 0;
    bool ok =
        append_fmt_checked(buf, buf_size, &off, "{") &&
        json_append_bool(buf, buf_size, &off, "is_git", ctx->is_git, true) &&
        json_append_bool(buf, buf_size, &off, "is_worktree", ctx->is_worktree, true) &&
        json_append_bool(buf, buf_size, &off, "is_detached", ctx->is_detached, true) &&
        json_append_bool(buf, buf_size, &off, "root_exists", ctx->root_exists, true) &&
        json_append_string(buf, buf_size, &off, "canonical_root", ctx->canonical_root, true) &&
        json_append_string(buf, buf_size, &off, "worktree_root", ctx->worktree_root, true) &&
        json_append_string(buf, buf_size, &off, "git_common_dir", ctx->git_common_dir, true) &&
        json_append_string(buf, buf_size, &off, "branch", ctx->branch, true) &&
        json_append_string(buf, buf_size, &off, "head_sha", ctx->head_sha, true) &&
        json_append_string(buf, buf_size, &off, "base_sha", ctx->base_sha, false) &&
        append_fmt_checked(buf, buf_size, &off, "}");
    if (!ok) {
        if (buf_size > 0) {
            buf[0] = '\0';
        }
        return 0;
    }
    return off;
}

char *cbm_git_context_props_json_alloc(const cbm_git_context_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    const char *values[] = {
        ctx->canonical_root, ctx->worktree_root, ctx->git_common_dir,
        ctx->branch,         ctx->head_sha,      ctx->base_sha,
    };
    size_t capacity = CBM_SZ_512;
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        size_t len = values[i] ? strlen(values[i]) : 0;
        if (len > (SIZE_MAX - capacity) / 6) {
            return NULL;
        }
        capacity += len * 6;
    }
    if (capacity > INT_MAX) {
        return NULL;
    }
    char *json = (char *)malloc(capacity);
    if (!json) {
        return NULL;
    }
    if (cbm_git_context_props_json(ctx, json, (int)capacity) <= 0) {
        free(json);
        return NULL;
    }
    return json;
}
