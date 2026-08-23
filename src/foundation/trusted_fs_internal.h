#ifndef CBM_TRUSTED_FS_INTERNAL_H
#define CBM_TRUSTED_FS_INTERNAL_H

#ifdef _WIN32

#include <stdint.h>

typedef void (*cbm_trusted_root_before_final_open_hook_fn)(void *context);

/* Test-only seam: the callback runs after every relative ancestor is pinned
 * and immediately before the final data handle is opened. */
void cbm_trusted_root_set_before_final_open_hook_for_test(
    cbm_trusted_root_before_final_open_hook_fn hook, void *context);

/* The production CreateFileW call consumes this exact flag value. */
uint32_t cbm_trusted_root_final_open_flags_for_test(void);

#endif

/* Keep the final directory strict while allowing writes in pinned ancestors. */
int cbm_trusted_root_open_mutable_ancestors(const char *root_path, cbm_trusted_root_t **out);

/* Permit child mutation only after the caller has pinned a non-deletable
 * child, so the final directory cannot be retagged as a reparse point. */
int cbm_trusted_root_upgrade_mutable_children(cbm_trusted_root_t *root, const char *root_path);

#endif
