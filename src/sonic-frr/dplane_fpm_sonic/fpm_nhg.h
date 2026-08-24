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
	struct prefix resolved_prefix; /* resolving prefix, when known */
	vrf_id_t vrf_id;
	/*
	 * Zebra NHG id this object resolved through (PR #19252 resolved_via).
	 * Not part of identity — it is derivable from the resolution, which is
	 * already reflected in the children (L-B) or in the gate (SRv6 leaf).
	 * Kept because by_rib_id maps it straight onto the dplane object of the
	 * resolving group, which is the cheap handle for a PIC-style repair.
	 */
	uint32_t resolved_via;
	/*
	 * Distinct zebra NHG ids that referenced this object, mirrored by the
	 * tables' by_rib_id reverse index (fpm_nhg_record_rib_id()). Grown one
	 * id at a time and never evicted: the index is only trustworthy if the
	 * object remembers every id pointing at it, both to answer a reverse
	 * lookup and to release exactly its own entries when it dies. Bounded
	 * by the number of zebra NHEs that map here, 4 bytes each.
	 */
	uint32_t *rib_nhg_ids;
	uint16_t rib_nhg_id_count, rib_nhg_id_cap;
	uint16_t num_children;
	struct fpm_nhg_child *children; /* sorted by obj->hash */
};

/*
 * Route key: identifies a route the plugin has seen. The (table_id, afi,
 * prefix, src_p) tuple is the design's route_nhg_map key — the only memory
 * of "old" across route events (design §4.2.1).
 *
 * src_p carries dplane_ctx_get_src() for srcdest routes and is all-zero
 * (family AF_UNSPEC) otherwise: two srcdest routes sharing one destination
 * are distinct routes in the kernel/FIB, so they must not share one map
 * entry — sharing would make the second install unref the first one's
 * object and desync the peer.
 */
struct fpm_nhg_route_key {
	uint32_t table_id;
	uint8_t afi;
	struct prefix p;
	struct prefix src_p;
};

struct fpm_nhg_tables {
	struct hash *by_hash;
	struct hash *by_id;
	struct hash *route_map; /* fpm_nhg_route_key -> top (L-A) object */
	struct hash *by_rib_id; /* zebra NHG id -> object (reverse index) */
	/*
	 * (vrf, resolving prefix) -> the objects that resolved through it; see
	 * struct fpm_nhg_resolved_bucket.
	 */
	struct hash *by_resolved;
	uint32_t next_id;
	uint32_t *free_ids;
	uint32_t free_id_count, free_id_cap;
	/*
	 * counters (lifetime totals, never reset by a reconnect flush).
	 * dedupe_hits is cumulative lookups incl. rolled-back builds: a
	 * build that fails and rolls back keeps the hits it scored, so the
	 * counter tracks lookup behaviour, not surviving objects.
	 */
	uint64_t obj_created, obj_deleted, nhgfib_sent, dedupe_hits;
};

void fpm_nhg_tables_init(struct fpm_nhg_tables *t);
void fpm_nhg_tables_flush(struct fpm_nhg_tables *t);
void fpm_nhg_tables_fini(struct fpm_nhg_tables *t);
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
	/*
	 * count is bumped one object at a time and cap only doubles (from 16)
	 * when count reaches it, so cap stays the smallest power of two >=
	 * count. count itself is bounded by the number of objects one build
	 * creates, i.e. by the size of one route's nexthop tree (thousands at
	 * most) — five orders of magnitude below the 2^31 where the doubling
	 * would leave the uint32.
	 */
	uint32_t count, cap;
};

void fpm_nhg_staging_free(struct fpm_nhg_staging *s);
struct fpm_dplane_nhg *fpm_nhg_build(struct fpm_nhg_tables *t,
				     const struct nexthop *chain,
				     struct fpm_nhg_staging *newq);
void fpm_nhg_ref(struct fpm_dplane_nhg *obj);
void fpm_nhg_rollback(struct fpm_nhg_tables *t, struct fpm_nhg_staging *newq);

/*
 * DEL staging carries the payload BY VALUE, not the object pointer:
 * fpm_nhg_unref() stages the DEL and then frees the object in the same
 * call, so a pointer queue would hand the emitter a dangling object.
 * RTM_DELNHGFIB needs nothing but the id, so one uint32 per entry is the
 * whole payload.
 */
struct fpm_nhg_del_entry {
	uint32_t dplane_id;
};

struct fpm_nhg_del_queue {
	struct fpm_nhg_del_entry *ids; /* parent-before-child DEL order */
	/*
	 * Same growth argument as fpm_nhg_staging: cap doubles (from 16) only
	 * when count reaches it, so cap is the smallest power of two >= count.
	 * count is bounded by the number of live objects the tables hold, and
	 * every one of those costs more than a hundred heap bytes, so reaching
	 * the 2^31 where the doubling would leave the uint32 would need
	 * hundreds of gigabytes of NHG state.
	 */
	uint32_t count, cap;
};

void fpm_nhg_del_queue_free(struct fpm_nhg_del_queue *q);
/* Empty the queue but keep its allocation (a queue reused across batches). */
void fpm_nhg_del_queue_reset(struct fpm_nhg_del_queue *q);
void fpm_nhg_unref(struct fpm_nhg_tables *t, struct fpm_dplane_nhg *obj,
		   struct fpm_nhg_del_queue *delq);

struct fpm_dplane_nhg *fpm_nhg_route_get(struct fpm_nhg_tables *t,
					 const struct fpm_nhg_route_key *k);
void fpm_nhg_route_set(struct fpm_nhg_tables *t,
		       const struct fpm_nhg_route_key *k,
		       struct fpm_dplane_nhg *obj, uint32_t rib_id);
struct fpm_dplane_nhg *fpm_nhg_route_pop(struct fpm_nhg_tables *t,
					 const struct fpm_nhg_route_key *k);
/*
 * Record that zebra NHG id `rib_id` maps to `obj`, and point the by_rib_id
 * reverse index at it. A zebra id resolves to one object at a time, so the
 * newest recorder wins; the losing object keeps the id in its own list (it
 * was referenced by it) but no longer owns the index entry.
 */
void fpm_nhg_record_rib_id(struct fpm_nhg_tables *t,
			   struct fpm_dplane_nhg *obj, uint32_t rib_id);
/*
 * Release one route's claim on a (rib id -> object) mapping. Called from the
 * route_map accessors; the mapping disappears once the last route drops it.
 */
void fpm_nhg_release_rib_id(struct fpm_nhg_tables *t,
			    struct fpm_dplane_nhg *obj, uint32_t rib_id);
/* Reverse lookup: zebra NHG id -> dplane object, NULL when unmapped. */
struct fpm_dplane_nhg *fpm_nhg_lookup_rib_id(struct fpm_nhg_tables *t,
					     uint32_t rib_id);

/*
 * Resolving-prefix index: (vrf, resolving prefix) -> every live dplane NHG
 * object that resolved through that prefix. The dplane-side equivalent of
 * zebra's NHT registration list, and the reason a route event can find its
 * blast radius with one hash probe instead of a table scan.
 *
 * Maintained wherever obj->resolved_prefix is set: on object creation, on the
 * leaf dedupe refresh that can re-point a resolution, and on object removal
 * (fpm_nhg_remove(), which every destruction path goes through). Objects
 * without a resolving prefix are not indexed, so the table is bounded by the
 * number of distinct resolving prefixes rather than by the object count.
 *
 * Like route_map and by_rib_id, a bucket holds borrowed object pointers and
 * takes no refcount; every object is unindexed before it is freed.
 */
struct fpm_nhg_resolved_bucket {
	vrf_id_t vrf_id;
	struct prefix p;
	struct fpm_dplane_nhg **objs;
	/*
	 * Same growth rule as the other arrays here: cap doubles from 8 only
	 * when count reaches it. count is the number of objects resolving
	 * through one prefix, bounded by the live object count.
	 */
	uint32_t count, cap;
};

/*
 * Every object resolving through (vrf_id, p), or NULL when none does. The
 * bucket is owned by the tables and is invalidated by the next object
 * creation or removal, so it must be consumed before the tables are touched
 * again.
 */
const struct fpm_nhg_resolved_bucket *
fpm_nhg_resolved_lookup(struct fpm_nhg_tables *t, vrf_id_t vrf_id,
			const struct prefix *p);

/*
 * Show helpers (design D13).
 *
 * The caller MUST hold `fnc->obuf_mutex` across the whole call: the tables
 * and the counters in `struct fpm_nhg_tables` are written under that mutex
 * by both the FPM pthread and the zebra main thread, so a vty-thread reader
 * has to take it too. The callback runs inside that critical section, so it
 * must not block or re-enter the tables.
 */
/* Callback invoked once per object, ascending dplane id. */
typedef void (*fpm_nhg_walk_cb)(const struct fpm_dplane_nhg *obj, void *arg);
void fpm_nhg_walk(struct fpm_nhg_tables *t, fpm_nhg_walk_cb cb, void *arg);
uint32_t fpm_nhg_count(struct fpm_nhg_tables *t);

/* Level of a derived dplane NHG object, as shown by `show fpm nhg-fib`. */
const char *fpm_nhg_level_str(uint8_t level);

#endif /* _FPM_NHG_H */
