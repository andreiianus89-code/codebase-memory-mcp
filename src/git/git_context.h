#ifndef CBM_GIT_CONTEXT_H
#define CBM_GIT_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>
#include "foundation/trusted_fs.h"

typedef struct {
    bool is_git;
    bool is_worktree;
    bool is_detached;
    bool root_exists;
    char *input_path;
    char *worktree_root;
    char *git_dir;
    char *git_common_dir;
    char *canonical_root;
    char *branch;
    char *branch_slug;
    char *head_sha;
    char *base_sha;
} cbm_git_context_t;

int cbm_git_context_resolve(const char *path, cbm_git_context_t *out);
int cbm_git_context_resolve_trusted(const char *path, const cbm_trusted_root_t *root,
                                    cbm_git_context_t *out);
void cbm_git_context_free(cbm_git_context_t *ctx);
char *cbm_git_context_branch_qn(const char *project_name, const cbm_git_context_t *ctx);
int cbm_git_context_props_json(const cbm_git_context_t *ctx, char *buf, int buf_size);

/* Heap-allocated variant with capacity derived from the context strings.
 * Caller frees the returned JSON. */
char *cbm_git_context_props_json_alloc(const cbm_git_context_t *ctx);

/* List paths tracked by Git, relative to repo_path. The returned array is
 * sorted and deduplicated. Filenames are read from `git ls-files -z`, so
 * whitespace and newlines are preserved. */
int cbm_git_list_tracked_files(const char *repo_path, char ***out, int *count);
int cbm_git_list_tracked_files_trusted(const char *repo_path, const cbm_trusted_root_t *root,
                                       char ***out, int *count);
void cbm_git_free_tracked_files(char **files, int count);

/* Deterministic instrumentation for trusted-runner regression/perf tests. */
void cbm_git_trusted_command_count_reset_for_tests(void);
uint64_t cbm_git_trusted_command_count_for_tests(void);

#endif
