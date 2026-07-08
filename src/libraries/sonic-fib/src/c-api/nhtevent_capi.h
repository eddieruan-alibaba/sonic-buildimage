#ifndef NHTEVENT_CAPI_H
#define NHTEVENT_CAPI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declare — callers include "src/c_nhtevent.h" (with src/ prefix)
 * to obtain the full struct definition. */
struct C_NhtEvent;

/*
 * Encode a NhtEvent into a JSON string.
 * Caller owns the returned pointer and must free() it.
 * Returns NULL on error (invalid args or allocation failure).
 *
 * All prefix strings must be non-NULL and null-terminated.
 */
char *nht_event_encode(
    const char *rnh_prefix,
    const char *prev_resolved_prefix,
    uint32_t    prev_resolved_nhg_id,
    const char *curr_resolved_prefix,
    uint32_t    curr_resolved_nhg_id);

/*
 * Decode a JSON string into C_NhtEvent.
 * Returns 0 on success, non-zero on error.
 * Prefix fields in out are C-strings of length up to C_NHTEVENT_PREFIX_STR_LEN.
 */
int nht_event_decode(const char *json_str, struct C_NhtEvent *out);

#ifdef __cplusplus
}
#endif

#endif
