#ifndef CBM_ARTIFACT_INTERNAL_H
#define CBM_ARTIFACT_INTERNAL_H

/* Deterministic concurrency seams. Production leaves both hooks NULL. */
typedef void (*cbm_artifact_snapshot_path_hook_fn)(const char *snapshot_path, void *context);
void cbm_artifact_set_snapshot_path_hook_for_test(cbm_artifact_snapshot_path_hook_fn hook,
                                                  void *context);

typedef void (*cbm_artifact_payload_published_hook_fn)(const char *project_name, void *context);
void cbm_artifact_set_payload_published_hook_for_test(cbm_artifact_payload_published_hook_fn hook,
                                                      void *context);

#endif /* CBM_ARTIFACT_INTERNAL_H */
