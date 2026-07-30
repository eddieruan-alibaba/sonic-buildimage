/*
 * FPM dplane NHG object model: 3-level Merkle-hashed nexthop group
 * objects with plugin-allocated uint32 dplane ids.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FPM_NHG_H
#define _FPM_NHG_H

#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/hash.h"

enum fpm_nhg_level { FPM_NHG_L_C = 0, FPM_NHG_L_B, FPM_NHG_L_A };

/*
 * nhg_flags bits carried in the NHGFIB JSON. RECURSIVE (1 << 3) mirrors
 * zebra_nhg.h NEXTHOP_GROUP_RECURSIVE; RECEIVED (1 << 12) mirrors the
 * fpmsyncd wire contract (nhgmgr.h NEXTHOP_GROUP_RECEIVED, checked as
 * (1 << 12)), so these must never change even if zebra_nhg.h flag
 * values move.
 */
#define FPM_NHG_FLAG_RECURSIVE (1 << 3)
#define FPM_NHG_FLAG_RECEIVED (1 << 12)

#define FPM_NHG_RIB_ID_TRACK 4

struct fpm_dplane_nhg;

struct fpm_nhg_child {
	struct fpm_dplane_nhg *obj;
	uint16_t weight;
};

struct fpm_dplane_nhg {
	uint64_t hash;        /* internal Merkle dedupe key */
	uint32_t dplane_id;   /* wire id: NHGFIB id / depends / RTA_NH_ID */
	uint32_t refcount;    /* parents + routes */
	uint8_t level;        /* enum fpm_nhg_level */
	uint32_t nhg_flags;   /* RECEIVED / RECURSIVE subset for JSON */
	struct nexthop *nh;   /* defining nexthop (dup'd) */
	struct prefix resolved_prefix; /* L-B only */
	vrf_id_t vrf_id;
	uint32_t rib_nhg_ids[FPM_NHG_RIB_ID_TRACK]; /* show only */
	uint8_t rib_nhg_id_count;
	uint16_t num_children;
	struct fpm_nhg_child *children; /* sorted by obj->hash */
};

/* Route-key -> object map lives in dplane_fpm_sonic.c (P8): key type owned there. */
struct fpm_nhg_tables {
	struct hash *by_hash;
	struct hash *by_id;
	uint32_t next_id;
	uint32_t *free_ids;
	uint32_t free_id_count, free_id_cap;
	/* counters */
	uint64_t obj_created, obj_deleted, nhgfib_sent, dedupe_hits;
};

void fpm_nhg_tables_init(struct fpm_nhg_tables *t);
void fpm_nhg_tables_flush(struct fpm_nhg_tables *t);
uint32_t fpm_nhg_id_alloc(struct fpm_nhg_tables *t);
void fpm_nhg_id_free(struct fpm_nhg_tables *t, uint32_t id);
uint64_t fpm_nhg_hash_leaf(const struct nexthop *nh);
uint64_t fpm_nhg_hash_group(uint8_t level, uint32_t nhg_flags,
			    const struct fpm_nhg_child *children,
			    uint16_t count, const struct prefix *resolved,
			    vrf_id_t vrf_id);
struct fpm_dplane_nhg *fpm_nhg_lookup_hash(struct fpm_nhg_tables *t, uint64_t hash);
struct fpm_dplane_nhg *fpm_nhg_lookup_id(struct fpm_nhg_tables *t, uint32_t id);
void fpm_nhg_insert(struct fpm_nhg_tables *t, struct fpm_dplane_nhg *obj);
void fpm_nhg_remove(struct fpm_nhg_tables *t, struct fpm_dplane_nhg *obj);

struct fpm_nhg_staging {
	struct fpm_dplane_nhg **objs;  /* objects needing RTM_NEWNHGFIB, child-first order */
	uint16_t count, cap;
};

void fpm_nhg_staging_free(struct fpm_nhg_staging *s);
struct fpm_dplane_nhg *fpm_nhg_build(struct fpm_nhg_tables *t,
				     const struct nexthop *chain,
				     struct fpm_nhg_staging *newq);
void fpm_nhg_ref(struct fpm_dplane_nhg *obj);
void fpm_nhg_rollback(struct fpm_nhg_tables *t, struct fpm_nhg_staging *newq);

#endif /* _FPM_NHG_H */
