/*
 * test_git_context.c — Tests for cbm_git_context_resolve(), focusing on
 * the canonical_root derivation for git worktrees and subdirectory projects.
 *
 * Issue #659: canonical_root was computed incorrectly for linked worktrees
 * and projects indexed from a subdirectory of the repository root.
 * git rev-parse --git-common-dir outputs a path relative to the -C directory
 * (input_path), not to worktree_root. Joining it with worktree_root and then
 * string-stripping "/.git" left unresolved ".." components in the result.
 *
 * POSIX fixtures shell out through system(); Windows fixtures use the native
 * argv/CreateProcess path so Git, UTF-8 paths, and NUL manifests are exercised
 * by the Windows CI runner too.
 *
 * Reproduce-first guard: canonical_root_subdir is the genuine RED-without-the-fix
 * guard — a repo indexed from a subdirectory yields a relative --git-common-dir
 * ("../.git"), so the unfixed code returns an un-normalized "<root>/subdir/.."
 * (verified FAIL on the unfixed derive_canonical_root; GREEN with the realpath
 * normalization). canonical_root_linked_worktree is a SUPPORTING INVARIANT, not
 * the #659 reproducer: on git that emits an *absolute* --git-common-dir for a
 * linked worktree (e.g. 2.48.x) the bug does not manifest there, so that test
 * passes with or without the fix. It still enforces the worktree->main-root
 * invariant and would catch the bug on git builds that emit a relative
 * worktree common-dir. canonical_root_repo_root is a baseline (no `..` to
 * normalize), not a guard.
 */
#include "test_framework.h"
#include "test_helpers.h"
#include "foundation/compat_fs.h"
#include "foundation/platform.h"
#include "foundation/trusted_fs.h"
#include "foundation/trusted_fs_internal.h"
#include "git/git_context.h"

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <limits.h>
#include <sys/stat.h>
#else
#include "foundation/win_utf8.h"
#include <windows.h>
#endif

/* POSIX-only shell helpers; Windows uses git_run_win below. */
#ifndef _WIN32
/* Run a git command inside dir, return 0 on success. */
static int git_run(const char *dir, const char *args) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "git -C \"%s\" %s >/dev/null 2>&1", dir, args);
    return system(cmd);
}

/* Create a minimal git repo at dir (init + empty commit so HEAD exists). */
static int make_git_repo(const char *dir) {
    if (th_mkdir_p(dir) != 0) return -1;
    if (git_run(dir, "init -q") != 0) return -1;
    if (git_run(dir, "config user.email test@example.com") != 0) return -1;
    if (git_run(dir, "config user.name Test") != 0) return -1;
    /* Create a file so HEAD points to a real commit. */
    char path[1024];
    snprintf(path, sizeof(path), "%s/.keep", dir);
    th_write_file(path, "");
    if (git_run(dir, "add .keep") != 0) return -1;
    if (git_run(dir, "commit -q -m init") != 0) return -1;
    return 0;
}
#endif /* _WIN32 */

#ifdef _WIN32
static int git_run_win(const char *dir, const char *const *args) {
    const char *argv[16] = {"git", "-C", dir};
    int count = 3;
    while (args && *args && count < (int)(sizeof(argv) / sizeof(argv[0])) - 1) {
        argv[count++] = *args++;
    }
    if (args && *args) {
        return -1;
    }
    argv[count] = NULL;
    return cbm_exec_no_shell(argv);
}

static int make_git_repo_win(const char *dir) {
    static const char *const init[] = {"init", "-q", NULL};
    static const char *const email[] = {"config", "user.email", "test@example.com", NULL};
    static const char *const name[] = {"config", "user.name", "Test", NULL};
    static const char *const add[] = {"add", "--", ".keep", NULL};
    static const char *const commit[] = {"commit", "-q", "-m", "init", NULL};
    char path[1024];
    if (th_mkdir_p(dir) != 0 || git_run_win(dir, init) != 0 ||
        git_run_win(dir, email) != 0 || git_run_win(dir, name) != 0) {
        return -1;
    }
    snprintf(path, sizeof(path), "%s/.keep", dir);
    return th_write_file(path, "") == 0 && git_run_win(dir, add) == 0 &&
                   git_run_win(dir, commit) == 0
               ? 0
               : -1;
}

static bool git_paths_equal_win(char *left, char *right) {
    return left && right &&
           strcmp(cbm_normalize_path_sep(left), cbm_normalize_path_sep(right)) == 0;
}

static void native_path_win(const char *path, char *out, size_t out_size) {
    snprintf(out, out_size, "%s", path ? path : "");
    for (char *cursor = out; *cursor; cursor++) {
        if (*cursor == '/') {
            *cursor = '\\';
        }
    }
}

typedef struct {
    const char *parent_path;
    const char *moved_path;
    const char *redirect_path;
    int calls;
    bool renamed;
    bool junction_created;
} trusted_read_replace_parent_ctx_t;

static void trusted_read_replace_parent_hook(void *opaque) {
    trusted_read_replace_parent_ctx_t *context = opaque;
    context->calls++;
    context->renamed =
        cbm_rename_replace(context->parent_path, context->moved_path) == 0;
    if (!context->renamed) {
        return;
    }
    char parent_native[1024];
    char redirect_native[1024];
    native_path_win(context->parent_path, parent_native, sizeof(parent_native));
    native_path_win(context->redirect_path, redirect_native, sizeof(redirect_native));
    const char *junction_argv[] = {"cmd.exe",      "/d",          "/c", "mklink", "/J",
                                   parent_native, redirect_native, NULL};
    context->junction_created = cbm_exec_no_shell(junction_argv) == 0;
}
#endif

/* ── canonical_root: normal repo indexed from its root ──────────── */

TEST(canonical_root_repo_root) {
#ifdef _WIN32
    char root[512];
    char *tmp = th_mktempdir("cbm_gitctx_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(root, sizeof(root), "%s", tmp);
    if (make_git_repo_win(root) != 0) {
        th_rmtree(root);
        FAIL("Git for Windows fixture setup failed");
    }
    cbm_git_context_t ctx = {0};
    ASSERT_EQ(cbm_git_context_resolve(root, &ctx), 0);
    ASSERT_TRUE(ctx.is_git);
    ASSERT_TRUE(git_paths_equal_win(ctx.canonical_root, ctx.worktree_root));
    cbm_git_context_free(&ctx);
    th_rmtree(root);
    PASS();
#else
    char *tmp = th_mktempdir("cbm_gitctx");
    if (!tmp) FAIL("th_mktempdir returned NULL");

    if (make_git_repo(tmp) != 0) {
        th_rmtree(tmp);
        SKIP_PLATFORM("git not available to init a repo");
    }

    cbm_git_context_t ctx = {0};
    int rc = cbm_git_context_resolve(tmp, &ctx);
    if (rc != 0 || !ctx.is_git) {
        cbm_git_context_free(&ctx);
        th_rmtree(tmp);
        FAIL("cbm_git_context_resolve failed or not a git repo");
    }

    char expected[4096];
    if (realpath(tmp, expected) == NULL) {
        cbm_git_context_free(&ctx);
        th_rmtree(tmp);
        FAIL("realpath(tmp) failed");
    }

    ASSERT_STR_EQ(ctx.canonical_root, expected);

    cbm_git_context_free(&ctx);
    th_rmtree(tmp);
    PASS();
#endif /* _WIN32 */
}

/* ── canonical_root: indexed from a subdirectory (issue #659) ─────
 * THE reproduce-first guard: from a subdir, --git-common-dir is relative, so the
 * unfixed derive_canonical_root joins it against worktree_root and strips "/.git"
 * textually, leaving canonical_root = "<root>/subdir/.." (or "<root>/..") instead
 * of "<root>". Verified RED on the unfixed code, GREEN with the realpath fix. */

TEST(canonical_root_subdir) {
#ifdef _WIN32
    char root[512];
    char *tmp = th_mktempdir("cbm_gitctx_sub_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(root, sizeof(root), "%s", tmp);
    if (make_git_repo_win(root) != 0) {
        th_rmtree(root);
        FAIL("Git for Windows fixture setup failed");
    }
    char subdir[768];
    snprintf(subdir, sizeof(subdir), "%s/scripts", root);
    ASSERT_EQ(th_mkdir_p(subdir), 0);
    cbm_git_context_t ctx = {0};
    ASSERT_EQ(cbm_git_context_resolve(subdir, &ctx), 0);
    ASSERT_TRUE(ctx.is_git);
    ASSERT_TRUE(git_paths_equal_win(ctx.canonical_root, ctx.worktree_root));
    cbm_git_context_free(&ctx);
    th_rmtree(root);
    PASS();
#else
    char *tmp = th_mktempdir("cbm_gitctx");
    if (!tmp) FAIL("th_mktempdir returned NULL");

    if (make_git_repo(tmp) != 0) {
        th_rmtree(tmp);
        SKIP_PLATFORM("git not available to init a repo");
    }

    /* Create a subdirectory inside the repo. */
    char subdir[1024];
    snprintf(subdir, sizeof(subdir), "%s/scripts", tmp);
    if (th_mkdir_p(subdir) != 0) {
        th_rmtree(tmp);
        FAIL("failed to create subdir");
    }

    cbm_git_context_t ctx = {0};
    int rc = cbm_git_context_resolve(subdir, &ctx);
    if (rc != 0 || !ctx.is_git) {
        cbm_git_context_free(&ctx);
        th_rmtree(tmp);
        FAIL("cbm_git_context_resolve on subdir failed or not a git repo");
    }

    /* canonical_root must equal the repo root, NOT "<repo>/.." or "<subdir>/..". */
    char expected[4096];
    if (realpath(tmp, expected) == NULL) {
        cbm_git_context_free(&ctx);
        th_rmtree(tmp);
        FAIL("realpath(tmp) failed");
    }

    ASSERT_STR_EQ(ctx.canonical_root, expected);

    /* Sanity: canonical_root must not contain ".." or end with a slash. */
    ASSERT(strstr(ctx.canonical_root, "..") == NULL);
    ASSERT(ctx.canonical_root[strlen(ctx.canonical_root) - 1] != '/');

    cbm_git_context_free(&ctx);
    th_rmtree(tmp);
    PASS();
#endif /* _WIN32 */
}

/* ── canonical_root: linked git worktree (supporting invariant) ────
 * NOT the #659 reproducer on modern git: git that emits an *absolute*
 * --git-common-dir for a linked worktree (e.g. 2.48.x) takes the path_is_absolute
 * branch, so the bug does not manifest and this passes with or without the fix.
 * It is kept as an invariant — canonical_root of a linked worktree must equal the
 * MAIN repo root (never the worktree root or its parent) — and would fail on a git
 * build that emits a *relative* worktree common-dir. The genuine RED-without-fix
 * guard for #659 is canonical_root_subdir above. */

TEST(canonical_root_linked_worktree) {
#ifdef _WIN32
    char main_root[512];
    char worktree[512];
    char *tmp = th_mktempdir("cbm_main_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(main_root, sizeof(main_root), "%s", tmp);
    tmp = th_mktempdir("cbm_worktree_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(worktree, sizeof(worktree), "%s", tmp);
    ASSERT_EQ(th_rmtree(worktree), 0);
    if (make_git_repo_win(main_root) != 0) {
        th_rmtree(main_root);
        FAIL("Git for Windows fixture setup failed");
    }
    static const char *const branch[] = {"branch", "wt-branch", NULL};
    const char *add_worktree[] = {"worktree", "add", worktree, "wt-branch", NULL};
    ASSERT_EQ(git_run_win(main_root, branch), 0);
    ASSERT_EQ(git_run_win(main_root, add_worktree), 0);
    cbm_git_context_t ctx = {0};
    ASSERT_EQ(cbm_git_context_resolve(worktree, &ctx), 0);
    ASSERT_TRUE(ctx.is_git);
    ASSERT_TRUE(ctx.is_worktree);
    cbm_git_context_t main_ctx = {0};
    ASSERT_EQ(cbm_git_context_resolve(main_root, &main_ctx), 0);
    ASSERT_TRUE(git_paths_equal_win(ctx.canonical_root, main_ctx.canonical_root));
    cbm_git_context_free(&main_ctx);
    cbm_git_context_free(&ctx);
    const char *remove_worktree[] = {"worktree", "remove", "--force", worktree, NULL};
    ASSERT_EQ(git_run_win(main_root, remove_worktree), 0);
    th_rmtree(main_root);
    PASS();
#else
    /* th_mktempdir() returns a static buffer — copy before the second call. */
    char main_tmp[256];
    char *raw = th_mktempdir("cbm_main");
    if (!raw) FAIL("th_mktempdir returned NULL");
    strncpy(main_tmp, raw, sizeof(main_tmp) - 1);
    main_tmp[sizeof(main_tmp) - 1] = '\0';

    char wt_tmp[256];
    raw = th_mktempdir("cbm_worktree");
    if (!raw) FAIL("th_mktempdir returned NULL");
    strncpy(wt_tmp, raw, sizeof(wt_tmp) - 1);
    wt_tmp[sizeof(wt_tmp) - 1] = '\0';

    /* Remove the worktree dir first — git worktree add creates it. */
    th_rmtree(wt_tmp);

    if (make_git_repo(main_tmp) != 0) {
        th_rmtree(main_tmp);
        SKIP_PLATFORM("git not available to init a repo");
    }

    /* Create a branch for the worktree. */
    if (git_run(main_tmp, "branch wt-branch") != 0) {
        th_rmtree(main_tmp);
        FAIL("failed to create branch for worktree");
    }

    /* Add a linked worktree. */
    char wt_cmd[1024];
    snprintf(wt_cmd, sizeof(wt_cmd), "worktree add \"%s\" wt-branch", wt_tmp);
    if (git_run(main_tmp, wt_cmd) != 0) {
        th_rmtree(wt_tmp);
        th_rmtree(main_tmp);
        SKIP_PLATFORM("git worktree add unavailable (git 2.5+ required)");
    }

    cbm_git_context_t ctx = {0};
    int rc = cbm_git_context_resolve(wt_tmp, &ctx);
    if (rc != 0 || !ctx.is_git) {
        cbm_git_context_free(&ctx);
        git_run(main_tmp, "worktree prune");
        th_rmtree(main_tmp);
        th_rmtree(wt_tmp);
        FAIL("cbm_git_context_resolve on linked worktree failed");
    }

    /* canonical_root must be the MAIN repo root, not the worktree root or its parent. */
    char expected[4096];
    if (realpath(main_tmp, expected) == NULL) {
        cbm_git_context_free(&ctx);
        git_run(main_tmp, "worktree prune");
        th_rmtree(main_tmp);
        th_rmtree(wt_tmp);
        FAIL("realpath(main_tmp) failed");
    }

    ASSERT_STR_EQ(ctx.canonical_root, expected);
    ASSERT(strstr(ctx.canonical_root, "..") == NULL);

    cbm_git_context_free(&ctx);
    git_run(main_tmp, "worktree prune");
    th_rmtree(main_tmp);
    th_rmtree(wt_tmp);
    PASS();
#endif /* _WIN32 */
}

TEST(tracked_files_are_sorted_and_exclude_untracked) {
#ifdef _WIN32
    char root[512];
    char *tmp = th_mktempdir("cbm_gittracked_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(root, sizeof(root), "%s", tmp);
    if (make_git_repo_win(root) != 0) {
        th_rmtree(root);
        FAIL("Git for Windows fixture setup failed");
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/z tracked.go", root);
    ASSERT_EQ(th_write_file(path, "package z\n"), 0);
    snprintf(path, sizeof(path), "%s/\xC3\xA9 tracked.go", root);
    ASSERT_EQ(th_write_file(path, "package unicode\n"), 0);
    static const char *const add[] = {"add", "--", ".", NULL};
    ASSERT_EQ(git_run_win(root, add), 0);
    snprintf(path, sizeof(path), "%s/a-untracked.go", root);
    ASSERT_EQ(th_write_file(path, "package a\n"), 0);

    char **files = NULL;
    int count = 0;
    ASSERT_EQ(cbm_git_list_tracked_files(root, &files, &count), 0);
    ASSERT_EQ(count, 3);
    ASSERT_STR_EQ(files[0], ".keep");
    ASSERT_STR_EQ(files[1], "z tracked.go");
    ASSERT_STR_EQ(files[2], "\xC3\xA9 tracked.go");
    cbm_git_free_tracked_files(files, count);
    th_rmtree(root);
    PASS();
#else
    char *tmp = th_mktempdir("cbm_gittracked");
    if (!tmp) FAIL("th_mktempdir returned NULL");

    if (make_git_repo(tmp) != 0) {
        th_rmtree(tmp);
        SKIP_PLATFORM("git not available to init a repo");
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/z tracked.go", tmp);
    th_write_file(path, "package z\n");
    snprintf(path, sizeof(path), "%s/back\\slash.go", tmp);
    th_write_file(path, "package backslash\n");
    snprintf(path, sizeof(path), "%s/line\nbreak.go", tmp);
    th_write_file(path, "package linebreak\n");
    if (git_run(tmp, "add -- .") != 0) {
        th_rmtree(tmp);
        FAIL("failed to stage tracked fixtures");
    }
    snprintf(path, sizeof(path), "%s/a-untracked.go", tmp);
    th_write_file(path, "package a\n");

    char **files = NULL;
    int count = 0;
    ASSERT_EQ(cbm_git_list_tracked_files(tmp, &files, &count), 0);
    ASSERT_EQ(count, 4);
    ASSERT_STR_EQ(files[0], ".keep");
    ASSERT_STR_EQ(files[1], "back\\slash.go");
    ASSERT_STR_EQ(files[2], "line\nbreak.go");
    ASSERT_STR_EQ(files[3], "z tracked.go");

    cbm_git_free_tracked_files(files, count);
    th_rmtree(tmp);
    PASS();
#endif /* _WIN32 */
}

TEST(trusted_context_batches_git_commands) {
#ifdef _WIN32
    char base[512];
    char root_path[768];
    char *tmp = th_mktempdir("cbm_gitbatch_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(base, sizeof(base), "%s", tmp);
    snprintf(root_path, sizeof(root_path), "%s/repo-\xC3\xA9-\xE6\x97\xA5\xE6\x9C\xAC",
             base);
    if (make_git_repo_win(root_path) != 0) {
        th_rmtree(base);
        FAIL("Git for Windows fixture setup failed");
    }
    char tracked_path[1024];
    snprintf(tracked_path, sizeof(tracked_path), "%s/z trusted \xC3\xA9.c", root_path);
    ASSERT_EQ(th_write_file(tracked_path, "int trusted_git;\n"), 0);
    static const char *const add[] = {"add", "--", ".", NULL};
    ASSERT_EQ(git_run_win(root_path, add), 0);
    cbm_trusted_root_t *root = NULL;
    ASSERT_EQ(cbm_trusted_root_open(root_path, &root), 0);
    ASSERT_NOT_NULL(root);

    cbm_git_trusted_command_count_reset_for_tests();
    cbm_git_context_t context = {0};
    ASSERT_EQ(cbm_git_context_resolve_trusted(root_path, root, &context), 0);
    ASSERT_TRUE(context.is_git);
    ASSERT_TRUE(git_paths_equal_win(context.canonical_root, context.worktree_root));
    ASSERT_EQ(cbm_git_trusted_command_count_for_tests(), 3);

    char **files = NULL;
    int count = 0;
    ASSERT_EQ(cbm_git_list_tracked_files_trusted(root_path, root, &files, &count), 0);
    ASSERT_EQ(count, 2);
    ASSERT_STR_EQ(files[0], ".keep");
    ASSERT_STR_EQ(files[1], "z trusted \xC3\xA9.c");
    ASSERT_EQ(cbm_git_trusted_command_count_for_tests(), 4);

    cbm_git_free_tracked_files(files, count);
    cbm_git_context_free(&context);
    cbm_trusted_root_close(root);
    th_rmtree(base);
    PASS();
#else
    char *tmp = th_mktempdir("cbm_gitbatch");
    ASSERT_NOT_NULL(tmp);
    if (make_git_repo(tmp) != 0) {
        th_rmtree(tmp);
        SKIP_PLATFORM("git not available to init a repo");
    }
    cbm_trusted_root_t *root = NULL;
    ASSERT_EQ(cbm_trusted_root_open(tmp, &root), 0);
    ASSERT_NOT_NULL(root);

    cbm_git_trusted_command_count_reset_for_tests();
    cbm_git_context_t context = {0};
    ASSERT_EQ(cbm_git_context_resolve_trusted(tmp, root, &context), 0);
    ASSERT_TRUE(context.is_git);
    ASSERT_EQ(cbm_git_trusted_command_count_for_tests(), 3);

    char **files = NULL;
    int count = 0;
    ASSERT_EQ(cbm_git_list_tracked_files_trusted(tmp, root, &files, &count), 0);
    ASSERT_EQ(count, 1);
    ASSERT_STR_EQ(files[0], ".keep");
    ASSERT_EQ(cbm_git_trusted_command_count_for_tests(), 4);

    cbm_git_free_tracked_files(files, count);
    cbm_git_context_free(&context);
    cbm_trusted_root_close(root);
    th_rmtree(tmp);
    PASS();
#endif
}

TEST(trusted_context_batch_failure_does_not_fallback) {
    char *tmp = th_mktempdir("cbm_gitbatch_fail");
    ASSERT_NOT_NULL(tmp);
#ifdef _WIN32
    static const char *const init[] = {"init", "-q", NULL};
    if (git_run_win(tmp, init) != 0) {
        th_rmtree(tmp);
        FAIL("Git for Windows fixture setup failed");
    }
#else
    if (th_mkdir_p(tmp) != 0 || git_run(tmp, "init -q") != 0) {
        th_rmtree(tmp);
        SKIP_PLATFORM("git not available to init a repo");
    }
#endif
    cbm_trusted_root_t *root = NULL;
    ASSERT_EQ(cbm_trusted_root_open(tmp, &root), 0);
    ASSERT_NOT_NULL(root);

    cbm_git_trusted_command_count_reset_for_tests();
    cbm_git_context_t context = {0};
    ASSERT_NEQ(cbm_git_context_resolve_trusted(tmp, root, &context), 0);
    ASSERT_EQ(cbm_git_trusted_command_count_for_tests(), 1);

    cbm_git_context_free(&context);
    cbm_trusted_root_close(root);
    th_rmtree(tmp);
    PASS();
}

static bool tracked_manifest_cap_is_bounded(void) {
    char *tmp = th_mktempdir("cbm_gitcap");
    const char *old_path = getenv("PATH");
    char *saved_path = old_path ? strdup(old_path) : NULL;
    char **files = NULL;
    int count = 0;
    bool ok = tmp && (!old_path || saved_path);
    char fake_git[1024] = {0};
    if (!ok) {
        goto cleanup;
    }
#ifdef _WIN32
    char payload[1024];
    char marker[1024];
    snprintf(fake_git, sizeof(fake_git), "%s/git.cmd", tmp);
    snprintf(payload, sizeof(payload), "%s/payload.bin", tmp);
    snprintf(marker, sizeof(marker), "%s/invoked.txt", tmp);
    FILE *oversized = cbm_fopen(payload, "wb");
    unsigned char block[8192] = {0};
    size_t remaining = (size_t)(64 * 1024 * 1024) + sizeof(block);
    ok = oversized != NULL;
    while (ok && remaining > 0) {
        size_t chunk = remaining < sizeof(block) ? remaining : sizeof(block);
        ok = fwrite(block, 1, chunk, oversized) == chunk;
        remaining -= chunk;
    }
    if (oversized) {
        ok = fclose(oversized) == 0 && ok;
    }
    ok = ok && th_write_file(fake_git,
                             "@echo off\r\n"
                             "type \"%~dp0payload.bin\"\r\n"
                             "> \"%~dp0invoked.txt\" echo drained\r\n") == 0 &&
         cbm_setenv("PATH", tmp, 1) == 0;
#else
    snprintf(fake_git, sizeof(fake_git), "%s/git", tmp);
    ok = th_write_file(fake_git,
                       "#!/bin/sh\n"
                       "/usr/bin/head -c 67117056 /dev/zero\n") == 0 &&
         chmod(fake_git, 0700) == 0 &&
         cbm_setenv("PATH", tmp, 1) == 0;
#endif
    if (!ok) {
        goto cleanup;
    }
    uint64_t started = cbm_now_ms();
    int rc = cbm_git_list_tracked_files(tmp, &files, &count);
    uint64_t elapsed = cbm_now_ms() - started;
    ok = rc != 0 && files == NULL && count == 0 && elapsed < 30000U;
#ifdef _WIN32
    ok = ok && cbm_file_exists(marker);
#endif

cleanup:
    cbm_git_free_tracked_files(files, count);
    if (saved_path) {
        (void)cbm_setenv("PATH", saved_path, 1);
    } else {
        (void)cbm_unsetenv("PATH");
    }
    free(saved_path);
    if (tmp) {
        th_rmtree(tmp);
    }
    return ok;
}

TEST(tracked_files_over_cap_fail_after_draining_in_bounded_time) {
    ASSERT_TRUE(tracked_manifest_cap_is_bounded());
    PASS();
}

#ifdef _WIN32
TEST(trusted_root_windows_unicode_deep_read_and_replacement_pin) {
    char base[512];
    char *tmp = th_mktempdir("cbm_trusted_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(base, sizeof(base), "%s", tmp);
    char root_path[768];
    char moved_path[768];
    snprintf(root_path, sizeof(root_path), "%s/repo-\xC3\xA9-\xE6\x97\xA5\xE6\x9C\xAC",
             base);
    snprintf(moved_path, sizeof(moved_path), "%s/moved", base);
    ASSERT_EQ(th_mkdir_p(root_path), 0);

    char relative[1024] = "";
    size_t used = 0;
    for (int i = 0; i < 9; i++) {
        int written = snprintf(relative + used, sizeof(relative) - used,
                               "segment-%02d-abcdefghijklmnop/", i);
        ASSERT_TRUE(written > 0 && (size_t)written < sizeof(relative) - used);
        used += (size_t)written;
    }
    int written = snprintf(relative + used, sizeof(relative) - used,
                           "fi\xC8\x99ier-\xE6\x97\xA5\xE6\x9C\xAC.c");
    ASSERT_TRUE(written > 0 && (size_t)written < sizeof(relative) - used);
    char full_path[2048];
    snprintf(full_path, sizeof(full_path), "%s/%s", root_path, relative);
    ASSERT_TRUE(strlen(full_path) > MAX_PATH);
    ASSERT_EQ(th_write_file(full_path, "int trusted_windows_probe;\n"), 0);

    cbm_trusted_root_t *root = NULL;
    ASSERT_EQ(cbm_trusted_root_open(root_path, &root), 0);
    ASSERT_NOT_NULL(root);
    ASSERT_TRUE(cbm_trusted_root_matches_path(root, root_path));
    ASSERT_FALSE(cbm_trusted_root_matches_path(root, base));
    unsigned char *data = NULL;
    size_t length = 0;
    struct stat status = {0};
    ASSERT_EQ(cbm_trusted_root_read_file(root, relative, 1024, &data, &length, &status), 0);
    ASSERT_EQ(length, strlen("int trusted_windows_probe;\n"));
    ASSERT_EQ(memcmp(data, "int trusted_windows_probe;\n", length), 0);
    ASSERT_EQ(status.st_size, (off_t)length);
    free(data);

    ASSERT_NEQ(cbm_rename_replace(root_path, moved_path), 0);
    ASSERT_TRUE(cbm_trusted_root_matches_path(root, root_path));
    cbm_trusted_root_close(root);
    ASSERT_EQ(cbm_rename_replace(root_path, moved_path), 0);
    ASSERT_EQ(th_rmtree(moved_path), 0);
    ASSERT_EQ(th_rmtree(base), 0);
    PASS();
}

TEST(trusted_root_windows_rejects_intermediate_and_final_reparse_points) {
    char base[512];
    char *tmp = th_mktempdir("cbm_trusted_reparse_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(base, sizeof(base), "%s", tmp);
    char root_path[768];
    char outside_path[768];
    char junction_path[768];
    char inside_path[768];
    char inside_junction_path[768];
    char outside_file[1024];
    char inside_file[1024];
    snprintf(root_path, sizeof(root_path), "%s/root", base);
    snprintf(outside_path, sizeof(outside_path), "%s/outside", base);
    snprintf(junction_path, sizeof(junction_path), "%s/jump", root_path);
    snprintf(inside_path, sizeof(inside_path), "%s/untracked", root_path);
    snprintf(inside_junction_path, sizeof(inside_junction_path), "%s/inside-jump",
             root_path);
    snprintf(outside_file, sizeof(outside_file), "%s/secret.c", outside_path);
    snprintf(inside_file, sizeof(inside_file), "%s/secret.c", inside_path);
    ASSERT_EQ(th_mkdir_p(root_path), 0);
    ASSERT_EQ(th_write_file(outside_file, "int outside;\n"), 0);
    ASSERT_EQ(th_write_file(inside_file, "int in_root_but_untracked;\n"), 0);

    char junction_native[768];
    char outside_native[768];
    char inside_junction_native[768];
    char inside_native[768];
    native_path_win(junction_path, junction_native, sizeof(junction_native));
    native_path_win(outside_path, outside_native, sizeof(outside_native));
    native_path_win(inside_junction_path, inside_junction_native,
                    sizeof(inside_junction_native));
    native_path_win(inside_path, inside_native, sizeof(inside_native));
    const char *junction_argv[] = {"cmd.exe",       "/d",           "/c", "mklink", "/J",
                                   junction_native, outside_native, NULL};
    const char *inside_junction_argv[] = {
        "cmd.exe", "/d", "/c", "mklink", "/J", inside_junction_native,
        inside_native, NULL};
    ASSERT_EQ(cbm_exec_no_shell(junction_argv), 0);
    ASSERT_EQ(cbm_exec_no_shell(inside_junction_argv), 0);

    cbm_trusted_root_t *root = NULL;
    ASSERT_EQ(cbm_trusted_root_open(root_path, &root), 0);
    ASSERT_NOT_NULL(root);
    cbm_trusted_root_t *reparse_root = NULL;
    ASSERT_NEQ(cbm_trusted_root_open(junction_path, &reparse_root), 0);
    ASSERT_NULL(reparse_root);
    unsigned char *data = NULL;
    size_t length = 0;
    ASSERT_NEQ(cbm_trusted_root_read_file(root, "jump/secret.c", 1024, &data, &length, NULL), 0);
    ASSERT_NULL(data);
    ASSERT_EQ(length, 0);
    ASSERT_NEQ(cbm_trusted_root_read_file(root, "inside-jump/secret.c", 1024,
                                          &data, &length, NULL),
               0);
    ASSERT_NULL(data);
    ASSERT_EQ(length, 0);
    ASSERT_NEQ(cbm_trusted_root_read_file(root, "jump", 1024, &data, &length, NULL), 0);
    ASSERT_NULL(data);
    ASSERT_EQ(length, 0);

    cbm_trusted_root_close(root);
    ASSERT_EQ(cbm_rmdir(junction_path), 0);
    ASSERT_EQ(cbm_rmdir(inside_junction_path), 0);
    ASSERT_EQ(th_rmtree(base), 0);
    PASS();
}

TEST(trusted_root_windows_pins_relative_ancestors_through_final_open) {
    char base[512];
    char *tmp = th_mktempdir("cbm_trusted_pin_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(base, sizeof(base), "%s", tmp);
    char root_path[768];
    char parent_path[768];
    char moved_path[768];
    char redirect_path[768];
    char tracked_file[1024];
    char redirect_file[1024];
    snprintf(root_path, sizeof(root_path), "%s/root", base);
    snprintf(parent_path, sizeof(parent_path), "%s/tracked", root_path);
    snprintf(moved_path, sizeof(moved_path), "%s/tracked-moved", root_path);
    snprintf(redirect_path, sizeof(redirect_path), "%s/untracked", root_path);
    snprintf(tracked_file, sizeof(tracked_file), "%s/source.c", parent_path);
    snprintf(redirect_file, sizeof(redirect_file), "%s/source.c", redirect_path);
    ASSERT_EQ(th_write_file(tracked_file, "int tracked_source;\n"), 0);
    ASSERT_EQ(th_write_file(redirect_file, "int untracked_source;\n"), 0);

    cbm_trusted_root_t *root = NULL;
    ASSERT_EQ(cbm_trusted_root_open(root_path, &root), 0);
    ASSERT_NOT_NULL(root);
    trusted_read_replace_parent_ctx_t context = {
        .parent_path = parent_path,
        .moved_path = moved_path,
        .redirect_path = redirect_path,
    };
    cbm_trusted_root_set_before_final_open_hook_for_test(
        trusted_read_replace_parent_hook, &context);
    unsigned char *data = NULL;
    size_t length = 0;
    int read_result = cbm_trusted_root_read_file(
        root, "tracked/source.c", 1024, &data, &length, NULL);
    cbm_trusted_root_set_before_final_open_hook_for_test(NULL, NULL);
    cbm_trusted_root_close(root);

    if (context.junction_created) {
        ASSERT_EQ(cbm_rmdir(parent_path), 0);
    }
    if (context.renamed) {
        ASSERT_EQ(cbm_rename_replace(moved_path, parent_path), 0);
    }
    ASSERT_EQ(context.calls, 1);
    ASSERT_FALSE(context.renamed);
    ASSERT_EQ(read_result, 0);
    ASSERT_EQ(length, strlen("int tracked_source;\n"));
    ASSERT_NOT_NULL(data);
    ASSERT_EQ(memcmp(data, "int tracked_source;\n", length), 0);
    free(data);
    ASSERT_TRUE((cbm_trusted_root_final_open_flags_for_test() &
                 FILE_FLAG_OPEN_REPARSE_POINT) != 0U);

    /* Prove the failed hook rename was blocked by the live ancestor pin, not
     * by an unrelated fixture or filesystem limitation. */
    ASSERT_EQ(cbm_rename_replace(parent_path, moved_path), 0);
    ASSERT_EQ(cbm_rename_replace(moved_path, parent_path), 0);
    ASSERT_EQ(th_rmtree(base), 0);
    PASS();
}

TEST(trusted_root_windows_mutable_children_preserves_root_identity) {
    char root[512];
    char moved[512];
    char temp[768];
    char final[768];
    char *tmp = th_mktempdir("cbm_trusted_mutable_win");
    ASSERT_NOT_NULL(tmp);
    snprintf(root, sizeof(root), "%s/root", tmp);
    snprintf(moved, sizeof(moved), "%s/moved", tmp);
    snprintf(temp, sizeof(temp), "%s/temp", root);
    snprintf(final, sizeof(final), "%s/final", root);
    ASSERT_EQ(th_mkdir_p(root), 0);
    ASSERT_EQ(th_write_file(temp, "payload"), 0);

    cbm_trusted_root_t *anchor = NULL;
    ASSERT_EQ(cbm_trusted_root_open_mutable_children(root, &anchor), 0);
    ASSERT_NOT_NULL(anchor);
    ASSERT_EQ(cbm_rename_replace(temp, final), 0);
    ASSERT_NEQ(cbm_rename_replace(root, moved), 0);
    ASSERT_TRUE(cbm_trusted_root_matches_path(anchor, root));
    cbm_trusted_root_close(anchor);
    ASSERT_EQ(cbm_rename_replace(root, moved), 0);
    th_rmtree(tmp);
    PASS();
}
#endif

#ifndef _WIN32
TEST(trusted_source_read_rejects_fifo_without_blocking) {
    char *tmp = th_mktempdir("cbm_trusted_fifo");
    ASSERT_NOT_NULL(tmp);
    char fifo_path[1024];
    snprintf(fifo_path, sizeof(fifo_path), "%s/tracked.c", tmp);
    ASSERT_EQ(mkfifo(fifo_path, 0600), 0);

    cbm_trusted_root_t *root = NULL;
    ASSERT_EQ(cbm_trusted_root_open(tmp, &root), 0);
    ASSERT_NOT_NULL(root);
    unsigned char *data = NULL;
    size_t length = 0;
    struct stat status = {0};
    uint64_t started = cbm_now_ms();
    int result =
        cbm_trusted_root_read_file(root, "tracked.c", 1024, &data, &length, &status);
    uint64_t elapsed = cbm_now_ms() - started;

    ASSERT_NEQ(result, 0);
    ASSERT_NULL(data);
    ASSERT_EQ(length, 0);
    ASSERT_LT(elapsed, 1000U);
    cbm_trusted_root_close(root);
    th_rmtree(tmp);
    PASS();
}
#endif

/* ── Suite ──────────────────────────────────────────────────────── */

SUITE(git_context) {
    RUN_TEST(canonical_root_repo_root);
    RUN_TEST(canonical_root_subdir);
    RUN_TEST(canonical_root_linked_worktree);
    RUN_TEST(tracked_files_are_sorted_and_exclude_untracked);
    RUN_TEST(trusted_context_batches_git_commands);
    RUN_TEST(trusted_context_batch_failure_does_not_fallback);
    RUN_TEST(tracked_files_over_cap_fail_after_draining_in_bounded_time);
#ifdef _WIN32
    RUN_TEST(trusted_root_windows_unicode_deep_read_and_replacement_pin);
    RUN_TEST(trusted_root_windows_rejects_intermediate_and_final_reparse_points);
    RUN_TEST(trusted_root_windows_pins_relative_ancestors_through_final_open);
    RUN_TEST(trusted_root_windows_mutable_children_preserves_root_identity);
#endif
#ifndef _WIN32
    RUN_TEST(trusted_source_read_rejects_fifo_without_blocking);
#endif
}
