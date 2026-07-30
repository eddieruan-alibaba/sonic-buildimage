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
#include "lib/mpls.h"
#include "lib/srv6.h"
#include "zebra/rib.h" /* DECLARE_MGROUP(ZEBRA) */

#include "zebra/fpm_nhg.h"

DEFINE_MTYPE_STATIC(ZEBRA, FPM_NHG, "FPM dplane nexthop group");

/* Bytes per encoded group member: child hash u64 + weight u8 */
#define FPM_NHG_CHILD_ENC_LEN 9
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

uint64_t fpm_nhg_hash_leaf(const struct nexthop *nh)
{
	struct {
		vrf_id_t vrf;
		uint8_t type, bh;
		int32_t ifindex;
		union g_addr gate;
		uint8_t label_type, nlabels;
		mpls_label_t labels[MPLS_MAX_LABELS];
		uint8_t nseg;
		struct in6_addr segs[SRV6_MAX_SIDS];
	} k;

	memset(&k, 0, sizeof(k)); /* deterministic padding */
	k.vrf = nh->vrf_id;
	k.type = nh->type;
	k.ifindex = nh->ifindex;
	if (nh->type == NEXTHOP_TYPE_BLACKHOLE)
		k.bh = nh->bh_type;
	else
		k.gate = nh->gate;
	k.label_type = nh->nh_label_type;
	if (nh->nh_label) {
		k.nlabels = MIN(nh->nh_label->num_labels, MPLS_MAX_LABELS);
		memcpy(k.labels, nh->nh_label->label,
		       k.nlabels * sizeof(mpls_label_t));
	}
	if (nh->nh_srv6 && nh->nh_srv6->seg6_segs) {
		k.nseg = MIN(nh->nh_srv6->seg6_segs->num_segs, SRV6_MAX_SIDS);
		memcpy(k.segs, nh->nh_srv6->seg6_segs->seg,
		       k.nseg * sizeof(struct in6_addr));
	}
	return fpm_nhg_digest(&k, sizeof(k));
}

uint64_t fpm_nhg_hash_group(uint8_t level, uint32_t nhg_flags,
			    const struct fpm_nhg_child *children,
			    uint16_t count, const struct prefix *resolved)
{
	uint32_t flags = nhg_flags &
			 (FPM_NHG_FLAG_RECURSIVE | FPM_NHG_FLAG_RECEIVED);
	size_t len = FPM_NHG_HDR_ENC_LEN +
		     (size_t)count * FPM_NHG_CHILD_ENC_LEN +
		     FPM_NHG_PFX_ENC_LEN;
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
		*p++ = children[i].weight;
	}
	if (level == FPM_NHG_L_B && resolved) {
		*p++ = resolved->family;
		*p++ = (uint8_t)resolved->prefixlen;
		blen = MIN(prefix_blen(resolved), 16);
		memcpy(p, &resolved->u.prefix, blen);
	}
	h = fpm_nhg_digest(buf, len);
	XFREE(MTYPE_FPM_NHG, buf);
	return h;
}

uint32_t fpm_nhg_id_alloc(struct fpm_nhg_tables *t)
{
	if (t->free_id_count)
		return t->free_ids[--t->free_id_count];
	return t->next_id++; /* starts at 1; 0 is the invalid sentinel */
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

void fpm_nhg_tables_init(struct fpm_nhg_tables *t)
{
	memset(t, 0, sizeof(*t));
	t->by_hash = hash_create(fpm_nhg_hash_key, fpm_nhg_hash_cmp,
				 "FPM dplane NHG by hash");
	t->by_id = hash_create(fpm_nhg_id_key, fpm_nhg_id_cmp,
			       "FPM dplane NHG by id");
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
	(void)hash_get(t->by_hash, obj, hash_alloc_intern);
	(void)hash_get(t->by_id, obj, hash_alloc_intern);
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

void fpm_nhg_tables_flush(struct fpm_nhg_tables *t)
{
	/*
	 * Objects live in both tables: empty by_id without freeing, then
	 * free each object once via by_hash. The tables themselves are
	 * kept (reused after reconnect).
	 */
	hash_clean(t->by_id, NULL);
	hash_clean(t->by_hash, fpm_nhg_obj_free);
	XFREE(MTYPE_FPM_NHG, t->free_ids);
	t->free_id_count = 0;
	t->free_id_cap = 0;
	t->next_id = 1;
	t->obj_created = 0;
	t->obj_deleted = 0;
	t->nhgfib_sent = 0;
	t->dedupe_hits = 0;
}
