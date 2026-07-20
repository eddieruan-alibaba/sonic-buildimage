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
 * Encode a C_NhtEvent struct into a JSON string.
 * Caller owns the returned pointer and must free() it.
 * Returns NULL on error (NULL arg or allocation/serialization failure).
 *
 * This is the struct-based entry used by the FRR FPM dplane provider,
 * matching the nexthopgroupfull_json_from_c_nhg_* convention: the C side
 * fills a C struct and the C-API converts it to a JSON string.
 */
char *nhtevent_json_from_c_nht(const struct C_NhtEvent *c_nht);

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
