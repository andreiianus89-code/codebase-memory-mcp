/*
 * trusted_fs.h — Handle-anchored, no-follow repository file reads.
 *
 * A lexical "realpath then fopen" check has a race: an ancestor can be
 * replaced after validation and before the file is opened.  This API keeps an
 * open handle to the admitted repository root and resolves every relative
 * component from that handle.  Callers receive the bytes read from the final
 * regular-file handle, never a pathname to reopen.
 */
#ifndef CBM_TRUSTED_FS_H
#define CBM_TRUSTED_FS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

typedef struct cbm_trusted_root cbm_trusted_root_t;

/* Open an existing, non-reparse directory as the repository anchor. */
int cbm_trusted_root_open(const char *root_path, cbm_trusted_root_t **out);

/* Release an anchor. NULL-safe. */
void cbm_trusted_root_close(cbm_trusted_root_t *root);

/* True only when path still names the same directory object as the anchor. */
bool cbm_trusted_root_matches_path(const cbm_trusted_root_t *root, const char *path);

/* POSIX: duplicate the anchored directory descriptor for fchdir/openat users.
 * Windows: returns -1 (the root handle itself denies rename/write sharing). */
int cbm_trusted_root_dup_native_fd(const cbm_trusted_root_t *root);

/*
 * Read one regular file below root. rel_path must be a non-empty repository
 * relative path with no empty, "." or ".." component.  Symlink/reparse final
 * components are rejected; POSIX ancestors are traversed with openat() and
 * O_NOFOLLOW.  On Windows the opened file handle's final path is checked
 * against the root handle, so an ancestor reparse race cannot escape root.
 *
 * max_bytes == 0 means SIZE_MAX.  out_data is NUL-terminated for parser
 * convenience, while out_len remains the exact byte count (embedded NUL is
 * preserved).  Caller owns out_data.
 */
int cbm_trusted_root_read_file(const cbm_trusted_root_t *root, const char *rel_path,
                               size_t max_bytes, unsigned char **out_data, size_t *out_len,
                               struct stat *out_status);

#endif /* CBM_TRUSTED_FS_H */
