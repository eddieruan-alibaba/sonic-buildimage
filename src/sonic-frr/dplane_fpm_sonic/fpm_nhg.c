/*
 * FPM dplane NHG object model implementation: Merkle hashing, id
 * allocation and by-hash / by-id table maintenance. Pure state, no
 * message emission.
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

#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include <string.h>

#include "lib/zebra.h"
#include "lib/memory.h"
#include "lib/sha256.h"
#include "lib/jhash.h"
#include "lib/mpls.h"
#include "lib/srv6.h"
#include "zebra/rib.h" /* DECLARE_MGROUP(ZEBRA) */

#include "zebra/fpm_nhg.h"

DEFINE_MTYPE_STATIC(ZEBRA, FPM_NHG, "FPM dplane nexthop group");

/* Bytes per encoded group member: child hash u64 + weight u16 BE */
#define FPM_NHG_CHILD_ENC_LEN 10
/* Group header: level u8 + masked nhg_flags u32 */
#define FPM_NHG_HDR_ENC_LEN 5
/* Resolved prefix: family u8 + prefixlen u8 + 16 addr bytes zero-padded */
#define FPM_NHG_PFX_ENC_LEN 18

static uint64_t fpm_nhg_digest(const void *buf, size_t len)
{
	unsigned char d[32];
	SHA256_CTX ctx;
	uint64_t out = 0;
	int i;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, len);
	SHA256_Final(d, &ctx);
	for (i = 0; i < 8; i++)
		out = (out << 8) | d[i];
	return out;
}

/*
 * Canonical leaf identity key: the exact bytes fpm_nhg_hash_leaf()
 * digests. Kept as a named struct so a hash-table hit can be verified
 * bit-for-bit against the candidate nexthop (collision handling) —
 * correctness never depends on hash uniqueness (design §6).
 */
struct fpm_nhg_leaf_key {
	vrf_id_t vrf;
	uint8_t type, bh;
	int32_t ifindex;
	union g_addr gate;
	/* src/rmap_src are emitted in the NHGFIB JSON, so they are part of
	 * leaf identity: leaves differing only there must not dedupe.
	 */
	union g_addr src;
	union g_addr rmap_src;
	uint32_t flags_subset; /* NEXTHOP_FLAGS_HASHED bits only */
	uint8_t label_type, nlabels;
	mpls_label_t labels[MPLS_MAX_LABELS];
	uint32_t seg6local_action;
	/* seg6local_context copied memberwise: the source struct
	 * carries interior padding (inside flv) whose content is
	 * unspecified wire data and must not reach the digest.
	 */
	struct in_addr s6l_nh4;
	struct in6_addr s6l_nh6;
	uint32_t s6l_table;
	int32_t s6l_ifindex;
	uint32_t s6l_flv_ops;
	uint8_t s6l_lcblock_len, s6l_lcnode_func_len;
	uint8_t s6l_block_len, s6l_node_len;
	uint8_t s6l_function_len, s6l_argument_len;
	uint8_t encap_behavior;
	uint8_t nseg;
	struct in6_addr segs[SRV6_MAX_SIDS];
};

static void fpm_nhg_leaf_key_fill(struct fpm_nhg_leaf_key *k,
				  const struct nexthop *nh)
{
	memset(k, 0, sizeof(*k)); /* deterministic padding */
	k->vrf = nh->vrf_id;
	k->type = nh->type;
	k->ifindex = nh->ifindex;
	if (nh->type == NEXTHOP_TYPE_BLACKHOLE)
		k->bh = nh->bh_type;
	else
		k->gate = nh->gate;
	k->src = nh->src;
	k->rmap_src = nh->rmap_src;
	k->flags_subset = nh->flags & NEXTHOP_FLAGS_HASHED;
	k->label_type = nh->nh_label_type;
	if (nh->nh_label) {
		k->nlabels = MIN(nh->nh_label->num_labels, MPLS_MAX_LABELS);
		memcpy(k->labels, nh->nh_label->label,
		       k->nlabels * sizeof(mpls_label_t));
	}
	if (nh->nh_srv6) {
		const struct seg6local_context *ctx =
			&nh->nh_srv6->seg6local_ctx;

		k->seg6local_action = nh->nh_srv6->seg6local_action;
		k->s6l_nh4 = ctx->nh4;
		k->s6l_nh6 = ctx->nh6;
		k->s6l_table = ctx->table;
		k->s6l_ifindex = ctx->ifindex;
		k->s6l_flv_ops = ctx->flv.flv_ops;
		k->s6l_lcblock_len = ctx->flv.lcblock_len;
		k->s6l_lcnode_func_len = ctx->flv.lcnode_func_len;
		k->s6l_block_len = ctx->block_len;
		k->s6l_node_len = ctx->node_len;
		k->s6l_function_len = ctx->function_len;
		k->s6l_argument_len = ctx->argument_len;
		if (nh->nh_srv6->seg6_segs) {
			k->encap_behavior =
				(uint8_t)nh->nh_srv6->seg6_segs->encap_behavior;
			k->nseg = MIN(nh->nh_srv6->seg6_segs->num_segs,
				      SRV6_MAX_SIDS);
			memcpy(k->segs, nh->nh_srv6->seg6_segs->seg,
			       k->nseg * sizeof(struct in6_addr));
		}
	}
}

uint64_t fpm_nhg_hash_leaf(const struct nexthop *nh)
{
	struct fpm_nhg_leaf_key k;

	fpm_nhg_leaf_key_fill(&k, nh);
	return fpm_nhg_digest(&k, sizeof(k));
}

/* Resolving vrf: vrf_id u32. Only meaningful for L-B objects, but always
 * encoded so the layout stays fixed; callers pass 0 for non-L-B levels. */
#define FPM_NHG_VRF_ENC_LEN 4

uint64_t fpm_nhg_hash_group(uint8_t level, uint32_t nhg_flags,
			    const struct fpm_nhg_child *children,
			    uint16_t count, const struct prefix *resolved,
			    vrf_id_t vrf_id)
{
	uint32_t flags = nhg_flags &
			 (FPM_NHG_FLAG_RECURSIVE | FPM_NHG_FLAG_RECEIVED);
	size_t len = FPM_NHG_HDR_ENC_LEN +
		     (size_t)count * FPM_NHG_CHILD_ENC_LEN +
		     FPM_NHG_PFX_ENC_LEN + FPM_NHG_VRF_ENC_LEN;
	uint8_t *buf, *p;
	uint64_t h;
	uint16_t i;
	int j, blen;

	/* byte-packed big-endian encode, zero-filled: no padding leaks */
	buf = XCALLOC(MTYPE_FPM_NHG, len);
	p = buf;
	*p++ = level;
	for (j = 3; j >= 0; j--)
		*p++ = (flags >> (8 * j)) & 0xff;
	for (i = 0; i < count; i++) {
		for (j = 7; j >= 0; j--)
			*p++ = (children[i].obj->hash >> (8 * j)) & 0xff;
		*p++ = (uint8_t)(children[i].weight >> 8);
		*p++ = (uint8_t)(children[i].weight & 0xff);
	}
	if (level == FPM_NHG_L_B && resolved) {
		*p++ = resolved->family;
		*p++ = (uint8_t)resolved->prefixlen;
		blen = MIN(prefix_blen(resolved), 16);
		memcpy(p, &resolved->u.prefix, blen);
	}
	/* vrf_id sits right after the 18-byte prefix block */
	p = buf + FPM_NHG_HDR_ENC_LEN +
	    (size_t)count * FPM_NHG_CHILD_ENC_LEN + FPM_NHG_PFX_ENC_LEN;
	for (j = 3; j >= 0; j--)
		*p++ = ((uint32_t)vrf_id >> (8 * j)) & 0xff;
	h = fpm_nhg_digest(buf, len);
	XFREE(MTYPE_FPM_NHG, buf);
	return h;
}

uint32_t fpm_nhg_id_alloc(struct fpm_nhg_tables *t)
{
	uint32_t id;

	if (t->free_id_count)
		return t->free_ids[--t->free_id_count];
	id = t->next_id++; /* starts at 1; 0 is the invalid sentinel */
	if (t->next_id == 0)
		t->next_id = 1; /* wrap: never hand out the 0 sentinel */
	return id;
}

void fpm_nhg_id_free(struct fpm_nhg_tables *t, uint32_t id)
{
	if (t->free_id_count == t->free_id_cap) {
		t->free_id_cap = t->free_id_cap ? t->free_id_cap * 2 : 64;
		t->free_ids = XREALLOC(MTYPE_FPM_NHG, t->free_ids,
				       t->free_id_cap * sizeof(uint32_t));
	}
	t->free_ids[t->free_id_count++] = id;
}

static unsigned int fpm_nhg_hash_key(const void *data)
{
	const struct fpm_dplane_nhg *obj = data;

	/* xor-fold the u64 Merkle hash down to the u32 bucket key */
	return (unsigned int)(obj->hash ^ (obj->hash >> 32));
}

static bool fpm_nhg_hash_cmp(const void *data1, const void *data2)
{
	return ((const struct fpm_dplane_nhg *)data1)->hash ==
	       ((const struct fpm_dplane_nhg *)data2)->hash;
}

static unsigned int fpm_nhg_id_key(const void *data)
{
	return ((const struct fpm_dplane_nhg *)data)->dplane_id;
}

static bool fpm_nhg_id_cmp(const void *data1, const void *data2)
{
	return ((const struct fpm_dplane_nhg *)data1)->dplane_id ==
	       ((const struct fpm_dplane_nhg *)data2)->dplane_id;
}

/*
 * route_nhg_map: (table_id, afi, prefix, src_p) -> top (L-A) object. Entries
 * are their own small allocation; the value is a borrowed pointer (the map's
 * refcount on the object is taken/released by the caller, not here).
 */
struct fpm_nhg_route_entry {
	struct fpm_nhg_route_key key;
	struct fpm_dplane_nhg *obj;
};

static unsigned int fpm_nhg_route_key_hash(const void *data)
{
	const struct fpm_nhg_route_entry *e = data;

	/* prefix_hash_key() (lib/prefix.h) zero-normalizes the prefix bytes;
	 * it handles AF_UNSPEC (the "no source prefix" case) as well.
	 */
	return jhash_2words(e->key.table_id, e->key.afi,
			    jhash_1word(prefix_hash_key(&e->key.src_p),
					prefix_hash_key(&e->key.p)));
}

/*
 * prefix_same() has no AF_UNSPEC case, so it reports two all-zero prefixes
 * as different. A non-srcdest route carries exactly such a zeroed src_p, so
 * that case is handled explicitly here.
 */
static bool fpm_nhg_src_same(const struct prefix *a, const struct prefix *b)
{
	if (a->family != b->family || a->prefixlen != b->prefixlen)
		return false;
	if (a->family == AF_UNSPEC)
		return true;
	return prefix_same(a, b) != 0;
}

static bool fpm_nhg_route_key_cmp(const void *data1, const void *data2)
{
	const struct fpm_nhg_route_entry *a = data1, *b = data2;

	return a->key.table_id == b->key.table_id &&
	       a->key.afi == b->key.afi && prefix_same(&a->key.p, &b->key.p) &&
	       fpm_nhg_src_same(&a->key.src_p, &b->key.src_p);
}

void fpm_nhg_tables_init(struct fpm_nhg_tables *t)
{
	memset(t, 0, sizeof(*t));
	t->by_hash = hash_create(fpm_nhg_hash_key, fpm_nhg_hash_cmp,
				 "FPM dplane NHG by hash");
	t->by_id = hash_create(fpm_nhg_id_key, fpm_nhg_id_cmp,
			       "FPM dplane NHG by id");
	t->route_map = hash_create(fpm_nhg_route_key_hash,
				   fpm_nhg_route_key_cmp,
				   "FPM dplane NHG route map");
	t->next_id = 1;
}

struct fpm_dplane_nhg *fpm_nhg_lookup_hash(struct fpm_nhg_tables *t,
					   uint64_t hash)
{
	struct fpm_dplane_nhg dummy = { .hash = hash };

	return hash_lookup(t->by_hash, &dummy);
}

struct fpm_dplane_nhg *fpm_nhg_lookup_id(struct fpm_nhg_tables *t, uint32_t id)
{
	struct fpm_dplane_nhg dummy = { .dplane_id = id };

	return hash_lookup(t->by_id, &dummy);
}

void fpm_nhg_insert(struct fpm_nhg_tables *t, struct fpm_dplane_nhg *obj)
{
	struct fpm_dplane_nhg *ret;

	ret = hash_get(t->by_hash, obj, hash_alloc_intern);
	assert(ret == obj);
	ret = hash_get(t->by_id, obj, hash_alloc_intern);
	assert(ret == obj);
}

void fpm_nhg_remove(struct fpm_nhg_tables *t, struct fpm_dplane_nhg *obj)
{
	hash_release(t->by_hash, obj);
	hash_release(t->by_id, obj);
}

static void fpm_nhg_obj_free(void *data)
{
	struct fpm_dplane_nhg *obj = data;

	/*
	 * obj->nh is one nexthop_dup() copy, never chained via ->next.
	 * nexthop_free() releases labels, srv6 data and the ->resolved
	 * chain the dup may have recursed into (lib/nexthop.c), so
	 * nexthops_free() is not needed.
	 */
	if (obj->nh)
		nexthop_free(obj->nh);
	XFREE(MTYPE_FPM_NHG, obj->children);
	XFREE(MTYPE_FPM_NHG, obj);
}

static void fpm_nhg_route_entry_free(void *data)
{
	XFREE(MTYPE_FPM_NHG, data);
}

void fpm_nhg_tables_flush(struct fpm_nhg_tables *t)
{
	/*
	 * Objects live in both tables: empty by_id without freeing, then
	 * free each object once via by_hash. The tables themselves are
	 * kept (reused after reconnect). route_map entries only hold
	 * borrowed object pointers, so they go first.
	 */
	hash_clean(t->route_map, fpm_nhg_route_entry_free);
	hash_clean(t->by_id, NULL);
	hash_clean(t->by_hash, fpm_nhg_obj_free);
	XFREE(MTYPE_FPM_NHG, t->free_ids);
	t->free_id_count = 0;
	t->free_id_cap = 0;
	t->next_id = 1;
	/* Counters are lifetime totals; reconnect flush does not reset them. */
}

/*
 * Shutdown counterpart of flush: empty the tables, then destroy the table
 * structures themselves. Only for plugin teardown — after this the tables
 * must be re-inited before any further use.
 *
 * lib's hash_free() is static, so hash_clean_and_free() is the public
 * equivalent; the flush above already emptied every table, hence the NULL
 * free_func (nothing left to free) and the NULLed pointers it leaves behind.
 */
void fpm_nhg_tables_fini(struct fpm_nhg_tables *t)
{
	fpm_nhg_tables_flush(t);
	hash_clean_and_free(&t->route_map, NULL);
	hash_clean_and_free(&t->by_id, NULL);
	hash_clean_and_free(&t->by_hash, NULL);
}

/*
 * Build engine: post-order DFS decomposition of a route ctx nexthop
 * tree into deduplicated dplane NHG objects (design §4.2.1). Pure
 * state — no message emission; every newly created object is pushed
 * onto the caller's staging queue in child-first order (a child is
 * always created — and thus queued — before any parent referencing
 * it, and cache hits queue nothing), which is exactly the
 * RTM_NEWNHGFIB define-before-reference order and, reversed, the
 * rollback order.
 */

static void fpm_nhg_staging_push(struct fpm_nhg_staging *s,
				 struct fpm_dplane_nhg *obj)
{
	if (s->count == s->cap) {
		/*
		 * cap doubles only when count reaches it, so cap is the
		 * smallest power of two >= count; count is bounded by the
		 * object count of one route's nexthop tree (see the struct
		 * comment), so cap never approaches 2^31.
		 */
		s->cap = s->cap ? s->cap * 2 : 16;
		s->objs = XREALLOC(MTYPE_FPM_NHG, s->objs,
				   s->cap * sizeof(*s->objs));
	}
	s->objs[s->count++] = obj;
}

void fpm_nhg_staging_free(struct fpm_nhg_staging *s)
{
	XFREE(MTYPE_FPM_NHG, s->objs);
	s->count = 0;
	s->cap = 0;
}

/*
 * Collision handling (design §6): a by_hash hit is only reused after
 * a full content comparison. On mismatch (true 64-bit collision) the
 * key is deterministically re-derived by digesting the previous key
 * plus an incrementing salt byte, and the probe repeats — both the
 * original creation and every later lookup walk the same salt
 * sequence from the same base hash, so colliding objects chain onto
 * distinct perturbed keys and are still found. Bounded: more than
 * FPM_NHG_MAX_PROBES chained collisions is beyond astronomically
 * unlikely and asserts.
 */
#define FPM_NHG_MAX_PROBES 16

static uint64_t fpm_nhg_hash_perturb(uint64_t hash, uint8_t salt)
{
	uint8_t buf[9];
	int j;

	for (j = 0; j < 8; j++)
		buf[j] = (hash >> (8 * (7 - j))) & 0xff;
	buf[8] = salt;
	return fpm_nhg_digest(buf, sizeof(buf));
}

/*
 * Probe the by_hash table starting at *hash. Returns the matching
 * object (dedupe hit), or NULL with *hash updated to the first free
 * slot on the probe sequence (creation key).
 */
static struct fpm_dplane_nhg *
fpm_nhg_probe(struct fpm_nhg_tables *t, uint64_t *hash,
	      bool (*match)(const struct fpm_dplane_nhg *, const void *),
	      const void *arg)
{
	struct fpm_dplane_nhg *obj;
	int attempt;

	for (attempt = 0; attempt < FPM_NHG_MAX_PROBES; attempt++) {
		obj = fpm_nhg_lookup_hash(t, *hash);
		if (!obj)
			return NULL;
		if (match(obj, arg))
			return obj;
		*hash = fpm_nhg_hash_perturb(*hash, (uint8_t)(attempt + 1));
	}
	assert(!"fpm_nhg: hash probe sequence exhausted");
	return NULL;
}

static bool fpm_nhg_leaf_match(const struct fpm_dplane_nhg *obj,
			       const void *arg)
{
	struct fpm_nhg_leaf_key ko, kn;

	if (obj->level != FPM_NHG_L_C || obj->num_children != 0 || !obj->nh)
		return false;
	/* compare the exact canonical bytes the leaf hash digests */
	fpm_nhg_leaf_key_fill(&ko, obj->nh);
	fpm_nhg_leaf_key_fill(&kn, arg);
	return memcmp(&ko, &kn, sizeof(ko)) == 0;
}

static struct fpm_dplane_nhg *fpm_nhg_obj_new(struct fpm_nhg_tables *t,
					      uint64_t hash, uint8_t level,
					      struct fpm_nhg_staging *newq)
{
	struct fpm_dplane_nhg *obj;

	obj = XCALLOC(MTYPE_FPM_NHG, sizeof(*obj));
	obj->hash = hash;
	obj->dplane_id = fpm_nhg_id_alloc(t);
	obj->level = level;
	fpm_nhg_insert(t, obj);
	fpm_nhg_staging_push(newq, obj);
	t->obj_created++;
	return obj;
}

static struct fpm_dplane_nhg *fpm_nhg_get_leaf(struct fpm_nhg_tables *t,
					       const struct nexthop *nh,
					       struct fpm_nhg_staging *newq)
{
	struct fpm_dplane_nhg *obj;
	uint64_t hash;

	hash = fpm_nhg_hash_leaf(nh);
	obj = fpm_nhg_probe(t, &hash, fpm_nhg_leaf_match, nh);
	if (obj) {
		t->dedupe_hits++;
		return obj;
	}
	obj = fpm_nhg_obj_new(t, hash, FPM_NHG_L_C, newq);
	/* leaves have no ->resolved subtree; no_recurse dup == plain dup */
	obj->nh = nexthop_dup_no_recurse(nh, NULL);
	return obj;
}

/* Everything the group hash covers; used for post-hit verification. */
struct fpm_nhg_group_key {
	uint8_t level;
	uint32_t nhg_flags;
	const struct fpm_nhg_child *children; /* sorted by obj->hash */
	uint16_t count;
	const struct prefix *resolved; /* non-NULL iff level == L_B */
	vrf_id_t vrf_id;
};

static bool fpm_nhg_group_match(const struct fpm_dplane_nhg *obj,
				const void *arg)
{
	const struct fpm_nhg_group_key *key = arg;
	uint16_t i;

	if (obj->level != key->level || obj->nhg_flags != key->nhg_flags ||
	    obj->num_children != key->count)
		return false;
	for (i = 0; i < key->count; i++) {
		/*
		 * Child pointer equality is the correct deep comparison:
		 * children are themselves content-deduped, so an equal
		 * subtree is the same object.
		 */
		if (obj->children[i].obj != key->children[i].obj ||
		    obj->children[i].weight != key->children[i].weight)
			return false;
	}
	if (key->level == FPM_NHG_L_B) {
		if (obj->resolved_prefix.family != key->resolved->family ||
		    obj->resolved_prefix.prefixlen != key->resolved->prefixlen)
			return false;
		if (key->resolved->family != AF_UNSPEC &&
		    !prefix_same(&obj->resolved_prefix, key->resolved))
			return false;
		if (obj->vrf_id != key->vrf_id)
			return false;
	}
	return true;
}

static int fpm_nhg_child_cmp(const void *a, const void *b)
{
	const struct fpm_nhg_child *ca = a, *cb = b;

	if (ca->obj->hash < cb->obj->hash)
		return -1;
	if (ca->obj->hash > cb->obj->hash)
		return 1;
	/* Same deduped child may appear twice with different weights;
	 * tie-break so the encoded sequence is deterministic.
	 */
	if (ca->weight < cb->weight)
		return -1;
	if (ca->weight > cb->weight)
		return 1;
	return 0;
}

/*
 * The L-B resolving info (PR #19252 resolved_addr/resolved_len on the
 * recursive parent nexthop) participates in the L-B group hash, so it
 * is derived from the parent BEFORE recursing and passed down —
 * never patched onto the child object after hashing.
 */
static void fpm_nhg_resolved_prefix(const struct nexthop *nh,
				    struct prefix *p)
{
	/* lib ipaddr2prefix() is static in prefix.c: convert manually */
	memset(p, 0, sizeof(*p));
	switch (nh->resolved_addr.ipa_type) {
	case IPADDR_V4:
		p->family = AF_INET;
		p->u.prefix4 = nh->resolved_addr.ipaddr_v4;
		break;
	case IPADDR_V6:
		p->family = AF_INET6;
		p->u.prefix6 = nh->resolved_addr.ipaddr_v6;
		break;
	case IPADDR_NONE:
		p->family = AF_UNSPEC;
		break;
	}
	p->prefixlen = nh->resolved_len;
}

static struct fpm_dplane_nhg *
fpm_nhg_build_group(struct fpm_nhg_tables *t, const struct nexthop *chain,
		    enum fpm_nhg_level level,
		    const struct nexthop *defining_nh,
		    const struct prefix *resolved, vrf_id_t vrf_id,
		    struct fpm_nhg_staging *newq);

/*
 * Resolve every member of chain to a child object. Same-level
 * traversal uses ->next only; ->resolved subtrees are entered
 * exclusively through the L-B recursion (never ALL_NEXTHOPS, which
 * would flatten the tree).
 *
 * A member flagged RECURSIVE but with no ->resolved chain is skipped
 * entirely: it is an unresolved recursive nexthop, i.e. nothing that can
 * be installed. Treating it as an L-C leaf would publish its (unresolved)
 * gate as a real forwarding entry. A recursive member whose whole resolved
 * chain turns out to be unresolvable (fpm_nhg_build_group() returns NULL
 * without having created anything) is skipped for exactly the same reason:
 * failing the whole context there would drop a route that may still have
 * perfectly usable other members. *count therefore reports how many
 * members were actually collected, which may be less than the member
 * count of the chain — and may be 0, which the caller turns into a failed
 * group build.
 *
 * Returns 0, or -1 if any child failed for a reason other than "nothing
 * installable" (partial creations stay queued; the caller rolls back).
 */
static int fpm_nhg_collect_children(struct fpm_nhg_tables *t,
				    const struct nexthop *chain,
				    struct fpm_nhg_child *children,
				    uint16_t *count, bool *any_recursive,
				    struct fpm_nhg_staging *newq)
{
	const struct nexthop *nh;
	struct fpm_dplane_nhg *child;
	struct prefix rp;
	uint32_t staged;
	uint16_t i = 0;

	for (nh = chain; nh; nh = nh->next) {
		if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
			if (!nh->resolved)
				continue; /* unresolved: not installable */
			fpm_nhg_resolved_prefix(nh, &rp);
			staged = newq->count;
			child = fpm_nhg_build_group(t, nh->resolved,
						    FPM_NHG_L_B, nh, &rp,
						    nh->vrf_id, newq);
			if (!child) {
				/*
				 * Objects already queued means the nested build
				 * hit a real error mid-way: propagate so the
				 * caller rolls them back. Otherwise nothing was
				 * created and this member simply has nothing
				 * installable behind it — skip it.
				 */
				if (newq->count != staged)
					return -1;
				continue;
			}
			/* only a member that contributed makes the group recursive */
			*any_recursive = true;
		} else {
			child = fpm_nhg_get_leaf(t, nh, newq);
			if (!child)
				return -1;
		}
		children[i].obj = child;
		children[i].weight = nh->weight;
		i++;
	}
	*count = i;
	return 0;
}

static struct fpm_dplane_nhg *
fpm_nhg_group_new(struct fpm_nhg_tables *t,
		  const struct fpm_nhg_group_key *key, uint64_t hash,
		  const struct nexthop *defining_nh,
		  struct fpm_nhg_child *children,
		  struct fpm_nhg_staging *newq)
{
	struct fpm_dplane_nhg *obj;
	uint16_t i;

	obj = fpm_nhg_obj_new(t, hash, key->level, newq);
	obj->nhg_flags = key->nhg_flags;
	/*
	 * Defining nexthop: L-B = the recursive parent (JSON needs its
	 * gate/type), L-A = none (JSON multi-builder walks children).
	 * nexthop_dup_no_recurse() (lib/nexthop.h) copies scalar fields
	 * incl. resolved_addr/len but not the ->resolved subtree — that
	 * subtree is already modeled as obj->children, so a recursing
	 * dup would only waste memory. NEXTHOP_FLAG_RECURSIVE stays set
	 * in the copy (JSON consumers use gate/type/flags only).
	 */
	if (defining_nh)
		obj->nh = nexthop_dup_no_recurse(defining_nh, NULL);
	if (key->level == FPM_NHG_L_B) {
		obj->resolved_prefix = *key->resolved;
		obj->vrf_id = key->vrf_id;
	}
	obj->num_children = key->count;
	obj->children = children; /* ownership transferred, sorted */
	for (i = 0; i < key->count; i++)
		fpm_nhg_ref(children[i].obj);
	return obj;
}

static struct fpm_dplane_nhg *
fpm_nhg_build_group(struct fpm_nhg_tables *t, const struct nexthop *chain,
		    enum fpm_nhg_level level,
		    const struct nexthop *defining_nh,
		    const struct prefix *resolved, vrf_id_t vrf_id,
		    struct fpm_nhg_staging *newq)
{
	struct fpm_nhg_child *children;
	struct fpm_nhg_group_key key;
	struct fpm_dplane_nhg *obj;
	const struct nexthop *nh;
	bool any_recursive = false;
	uint64_t hash;
	uint16_t nmembers = 0, n = 0;

	for (nh = chain; nh; nh = nh->next)
		nmembers++;
	if (nmembers == 0)
		return NULL;
	children = XCALLOC(MTYPE_FPM_NHG, nmembers * sizeof(*children));
	if (fpm_nhg_collect_children(t, chain, children, &n, &any_recursive,
				     newq) < 0) {
		XFREE(MTYPE_FPM_NHG, children);
		return NULL;
	}
	/*
	 * Every member was skipped as not installable (unresolved recursive
	 * nexthop, or a recursive nexthop with nothing installable behind it):
	 * NULL here consistently means "nothing to install", never "error".
	 */
	if (n == 0) {
		XFREE(MTYPE_FPM_NHG, children);
		return NULL;
	}
	/* single non-recursive member at top level: L-A == L-C, no wrapper */
	if (level == FPM_NHG_L_A && n == 1 && !any_recursive) {
		obj = children[0].obj;
		XFREE(MTYPE_FPM_NHG, children);
		return obj;
	}
	qsort(children, n, sizeof(*children), fpm_nhg_child_cmp);
	key.level = level;
	/*
	 * nhg_flags feeds the group hash below, so it has to be decided here.
	 *
	 * Only L-B carries RECURSIVE. RECEIVED is deliberately NOT set on a
	 * plain-IP L-A group: to fpmsyncd RECEIVED means "pre-resolution group,
	 * do not program". nhgmgr.cpp RIBNHGEntry::checkNeedCreateSonicNHGObj()
	 * bails out for a NORMAL (non-SRv6) entry that carries it —
	 *   "NextHop %d is a received NHG without SRv6 info, skip create sonic
	 *    object." -> m_create_sonic_nhg_obj = false
	 * so the group would never get a SONiC NHG object id and every route
	 * pointing at it would fail its RTA_NH_ID lookup.
	 *
	 * The one case where the consumer wants RECEIVED is SRv6:
	 * checkNeedCreateSonicPICObj() turns SRv6 + RECEIVED into
	 * SONIC_NHG_OBJ_TYPE_NHG_WITH_SRV6_PIC_CONTEXT. That path needs its own
	 * SRv6 aware decision (which object level carries the VPN SID) and is
	 * handled separately / still pending, so nothing sets RECEIVED yet.
	 */
	key.nhg_flags = (level == FPM_NHG_L_B ? FPM_NHG_FLAG_RECURSIVE : 0);
	key.children = children;
	key.count = n;
	key.resolved = (level == FPM_NHG_L_B) ? resolved : NULL;
	key.vrf_id = (level == FPM_NHG_L_B) ? vrf_id : 0;
	hash = fpm_nhg_hash_group(level, key.nhg_flags, children, n,
				  key.resolved, key.vrf_id);
	obj = fpm_nhg_probe(t, &hash, fpm_nhg_group_match, &key);
	if (obj) {
		/* cache hit stops recursion: no message, no new refs */
		t->dedupe_hits++;
		XFREE(MTYPE_FPM_NHG, children);
		return obj;
	}
	return fpm_nhg_group_new(t, &key, hash, defining_nh, children, newq);
}

/*
 * Public entry: always the top-level (L-A) chain of a route ctx; the
 * L-B recursion is internal. No resolving info at the top level.
 */
struct fpm_dplane_nhg *fpm_nhg_build(struct fpm_nhg_tables *t,
				     const struct nexthop *chain,
				     struct fpm_nhg_staging *newq)
{
	return fpm_nhg_build_group(t, chain, FPM_NHG_L_A, NULL, NULL, 0,
				   newq);
}

void fpm_nhg_ref(struct fpm_dplane_nhg *obj)
{
	obj->refcount++;
}

/*
 * Fully undo one fpm_nhg_build(): destroy every object it created, in
 * reverse (parent-first) staging order. Objects in newq hold no route
 * refs yet, so at each step the object's remaining refcount stems
 * only from later-queued (already removed) new parents — it must be 0
 * (asserted; this also verifies the child-first queue order).
 * Pre-existing children that gained +1 from a new parent are simply
 * decremented back to their original live count, never to 0.
 */
void fpm_nhg_rollback(struct fpm_nhg_tables *t, struct fpm_nhg_staging *newq)
{
	struct fpm_dplane_nhg *obj;
	uint32_t i;
	uint16_t c;

	for (i = newq->count; i > 0; i--) {
		obj = newq->objs[i - 1];
		assert(obj->refcount == 0);
		for (c = 0; c < obj->num_children; c++) {
			assert(obj->children[c].obj->refcount > 0);
			obj->children[c].obj->refcount--;
		}
		fpm_nhg_remove(t, obj);
		fpm_nhg_id_free(t, obj->dplane_id);
		fpm_nhg_obj_free(obj);
		t->obj_created--;
	}
	newq->count = 0;
}

/*
 * Deletion (design §4.2.1 "Deletion primitive"). Objects die only when
 * their refcount reaches 0 — no GC pass, no tree diffing.
 *
 * The DEL of a parent is staged BEFORE recursing into its children, so
 * the staged sequence is parent-before-child: fpmsyncd never sees a live
 * object whose depends have already been deleted.
 *
 * Staging is by value (dplane id only): the object is freed before this
 * function returns, so staging the pointer would hand the emitter freed
 * memory.
 *
 * id_free() vs DEL flush: the design requires that a freed id is not
 * reused before its DEL has been flushed. That holds even though the
 * caller now DEFERS the staged DELs to the head of its next batch,
 * because
 *   (a) within one ctx the whole fpm_nhg_build() runs before any unref,
 *       so ids this ctx frees cannot be popped by this ctx's allocations;
 *   (b) the deferred DELs are emitted at the HEAD of the next batch, i.e.
 *       ahead of every RTM_NEWNHGFIB in it, so a later ctx that pops a
 *       recycled id from the free list necessarily emits its NEW after
 *       that DEL in the byte stream.
 */
static void fpm_nhg_del_queue_push(struct fpm_nhg_del_queue *q, uint32_t id)
{
	if (q->count == q->cap) {
		/*
		 * cap doubles only when count reaches it, so cap is the
		 * smallest power of two >= count; count is bounded by the
		 * number of live objects (see the struct comment), so cap
		 * never approaches 2^31.
		 */
		q->cap = q->cap ? q->cap * 2 : 16;
		q->ids = XREALLOC(MTYPE_FPM_NHG, q->ids,
				  q->cap * sizeof(*q->ids));
	}
	q->ids[q->count++].dplane_id = id;
}

void fpm_nhg_del_queue_free(struct fpm_nhg_del_queue *q)
{
	XFREE(MTYPE_FPM_NHG, q->ids);
	q->count = 0;
	q->cap = 0;
}

void fpm_nhg_del_queue_reset(struct fpm_nhg_del_queue *q)
{
	q->count = 0;
}

void fpm_nhg_unref(struct fpm_nhg_tables *t, struct fpm_dplane_nhg *obj,
		   struct fpm_nhg_del_queue *delq)
{
	uint16_t i;

	assert(obj->refcount > 0);
	if (--obj->refcount > 0)
		return;

	fpm_nhg_del_queue_push(delq, obj->dplane_id);
	for (i = 0; i < obj->num_children; i++)
		fpm_nhg_unref(t, obj->children[i].obj, delq);
	fpm_nhg_remove(t, obj);
	fpm_nhg_id_free(t, obj->dplane_id);
	fpm_nhg_obj_free(obj);
	t->obj_deleted++;
}

/*
 * route_nhg_map accessors. The upsert flow is get-then-set: the caller
 * reads the old object first, installs the new one, then unrefs the old
 * (design §4.2.1 "Per-op handling").
 */
static void *fpm_nhg_route_entry_alloc(void *arg)
{
	const struct fpm_nhg_route_entry *ref = arg;
	struct fpm_nhg_route_entry *e;

	e = XCALLOC(MTYPE_FPM_NHG, sizeof(*e));
	e->key = ref->key;
	return e;
}

struct fpm_dplane_nhg *fpm_nhg_route_get(struct fpm_nhg_tables *t,
					 const struct fpm_nhg_route_key *k)
{
	struct fpm_nhg_route_entry ref = { .key = *k }, *e;

	e = hash_lookup(t->route_map, &ref);
	return e ? e->obj : NULL;
}

void fpm_nhg_route_set(struct fpm_nhg_tables *t,
		       const struct fpm_nhg_route_key *k,
		       struct fpm_dplane_nhg *obj)
{
	struct fpm_nhg_route_entry ref = { .key = *k }, *e;

	e = hash_get(t->route_map, &ref, fpm_nhg_route_entry_alloc);
	e->obj = obj; /* replaces any previous object: caller unrefs the old */
}

struct fpm_dplane_nhg *fpm_nhg_route_pop(struct fpm_nhg_tables *t,
					 const struct fpm_nhg_route_key *k)
{
	struct fpm_nhg_route_entry ref = { .key = *k }, *e;
	struct fpm_dplane_nhg *obj;

	e = hash_release(t->route_map, &ref);
	if (!e)
		return NULL;
	obj = e->obj;
	XFREE(MTYPE_FPM_NHG, e);
	return obj;
}

/*
 * Remember which zebra (rib) NHG ids were seen referencing this object.
 * Show-only mapping (design D13): a small dedup ring, oldest dropped
 * when full. Id 0 means "no zebra NHG" and is never recorded.
 */
void fpm_nhg_record_rib_id(struct fpm_dplane_nhg *obj, uint32_t rib_id)
{
	uint8_t i;

	if (rib_id == 0)
		return;
	for (i = 0; i < obj->rib_nhg_id_count; i++)
		if (obj->rib_nhg_ids[i] == rib_id)
			return;
	if (obj->rib_nhg_id_count < FPM_NHG_RIB_ID_TRACK) {
		obj->rib_nhg_ids[obj->rib_nhg_id_count++] = rib_id;
		return;
	}
	memmove(&obj->rib_nhg_ids[0], &obj->rib_nhg_ids[1],
		(FPM_NHG_RIB_ID_TRACK - 1) * sizeof(obj->rib_nhg_ids[0]));
	obj->rib_nhg_ids[FPM_NHG_RIB_ID_TRACK - 1] = rib_id;
}

/*
 * Show helpers (design D13). Callers MUST hold `fnc->obuf_mutex` — see the
 * declarations in fpm_nhg.h for the rationale.
 */
uint32_t fpm_nhg_count(struct fpm_nhg_tables *t)
{
	return (uint32_t)hashcount(t->by_id);
}

struct fpm_nhg_walk_state {
	const struct fpm_dplane_nhg **objs;
	uint32_t count, cap;
};

static void fpm_nhg_walk_collect(struct hash_bucket *bucket, void *arg)
{
	struct fpm_nhg_walk_state *w = arg;

	/*
	 * cap comes from hashcount() taken under the same lock as this walk,
	 * so it can never be exceeded; the guard is pure belt and braces.
	 */
	if (w->count >= w->cap)
		return;
	w->objs[w->count++] = bucket->data;
}

static int fpm_nhg_walk_id_cmp(const void *a, const void *b)
{
	const struct fpm_dplane_nhg *oa = *(const struct fpm_dplane_nhg *const *)a;
	const struct fpm_dplane_nhg *ob = *(const struct fpm_dplane_nhg *const *)b;

	if (oa->dplane_id < ob->dplane_id)
		return -1;
	if (oa->dplane_id > ob->dplane_id)
		return 1;
	return 0;
}

/*
 * hash_iterate() yields buckets in table order, i.e. arbitrary as far as the
 * dplane id is concerned. Show output has to be stable and comparable across
 * invocations, so collect the pointers first, sort them by id, and only then
 * hand them to the callback. The temporary array borrows the pointers; the
 * objects themselves stay owned by the tables.
 */
void fpm_nhg_walk(struct fpm_nhg_tables *t, fpm_nhg_walk_cb cb, void *arg)
{
	struct fpm_nhg_walk_state w = {};
	uint32_t i;

	w.cap = (uint32_t)hashcount(t->by_id);
	if (w.cap == 0)
		return;

	w.objs = XCALLOC(MTYPE_FPM_NHG, w.cap * sizeof(*w.objs));
	hash_iterate(t->by_id, fpm_nhg_walk_collect, &w);
	qsort(w.objs, w.count, sizeof(*w.objs), fpm_nhg_walk_id_cmp);
	for (i = 0; i < w.count; i++)
		cb(w.objs[i], arg);
	XFREE(MTYPE_FPM_NHG, w.objs);
}
