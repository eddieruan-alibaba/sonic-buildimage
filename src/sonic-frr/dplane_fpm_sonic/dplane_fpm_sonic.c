/*
 * Zebra dataplane plugin for Forwarding Plane Manager (FPM) using netlink.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
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

#include <arpa/inet.h>
#include <linux/seg6_iptunnel.h>
#include <linux/nexthop.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>

#include "lib/zebra.h"
#include <linux/rtnetlink.h>
#include "lib/json.h"
#include "lib/libfrr.h"
#include "lib/frratomic.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/ns.h"
#include "lib/frr_pthread.h"
#include "lib/termtable.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "lib/netlink_parser.h"
#include "zebra/debug.h"
#include "zebra/zebra_srv6.h"
#include "zebra/fpm_nhg.h"
#include "fpm/fpm.h"
#include "lib/srv6.h"
#include "lib/vrf.h"
#include <nexthopgroup/c_nexthopgroupfull.h>
#include <nexthopgroup/c-api/nexthopgroup_capi.h>

/* FIB log level constants, aligned with fib::LogLevel in nexthopgroup_debug.h */
enum fib_log_level {
	FIB_LOG_LEVEL_DEBUG = 0,
	FIB_LOG_LEVEL_INFO  = 1,
	FIB_LOG_LEVEL_WARN  = 2,
	FIB_LOG_LEVEL_ERROR = 3,
};

#define SOUTHBOUND_DEFAULT_ADDR INADDR_LOOPBACK
#define SOUTHBOUND_DEFAULT_PORT 2620
#define SEG6_SEGMENT_NAME_LEN 64
/**
 * FPM header:
 * {
 *   version: 1 byte (always 1),
 *   type: 1 byte (1 for netlink, 2 protobuf),
 *   len: 2 bytes (network order),
 * }
 *
 * This header is used with any format to tell the users how many bytes to
 * expect.
 */
#define FPM_HEADER_SIZE 4

/* Default SRv6 SID format values */
#define DEFAULT_SRV6_LOCALSID_FORMAT_BLOCK_LEN 32
#define DEFAULT_SRV6_LOCALSID_FORMAT_NODE_LEN 16
#define DEFAULT_SRV6_LOCALSID_FORMAT_FUNCTION_LEN 16
#define DEFAULT_SRV6_LOCALSID_FORMAT_ARGUMENT_LEN 0

/*
 * Time in seconds that if the other end is not responding
 * something terrible has gone wrong.  Let's fix that.
 */
#define DPLANE_FPM_NL_WEDGIE_TIME 15

/**
 * Custom Netlink TLVs
*/

/* Custom Netlink message types */
enum custom_nlmsg_types {
	RTM_NEWSRV6LOCALSID		= 1000,
	RTM_DELSRV6LOCALSID		= 1001,
	RTM_NEWPICCONTEXT		= 2000,
	RTM_DELPICCONTEXT		= 2001,
	RTM_NEWSRV6VPNROUTE		= 3000,
	RTM_DELSRV6VPNROUTE		= 3001,
	RTM_NEWSIDLIST			= 4000,
	RTM_DELSIDLIST			= 4001,
	RTM_NEWNHGFIB			= 5000,
	RTM_DELNHGFIB			= 5001,
};

/* Custom Netlink attribute types */
enum custom_rtattr_encap {
	FPM_ROUTE_ENCAP_SRV6		= 101,
};

enum custom_rtattr_srv6_localsid {
	FPM_SRV6_LOCALSID_UNSPEC			= 0,
	FPM_SRV6_LOCALSID_SID_VALUE			= 1,
	FPM_SRV6_LOCALSID_FORMAT			= 2,
	FPM_SRV6_LOCALSID_ACTION			= 3,
	FPM_SRV6_LOCALSID_VRFNAME			= 4,
	FPM_SRV6_LOCALSID_NH6				= 5,
	FPM_SRV6_LOCALSID_NH4				= 6,
	FPM_SRV6_LOCALSID_IIF				= 7,
	FPM_SRV6_LOCALSID_OIF				= 8,
	FPM_SRV6_LOCALSID_BPF				= 9,
	FPM_SRV6_LOCALSID_SIDLIST			= 10,
	FPM_SRV6_LOCALSID_ENCAP_SRC_ADDR	= 11,
	FPM_SRV6_LOCALSID_IFNAME			= 12,
};

enum custom_rtattr_encap_srv6 {
	FPM_ROUTE_ENCAP_SRV6_ENCAP_UNSPEC		= 0,
	FPM_ROUTE_ENCAP_SRV6_VPN_SID			= 1,
	FPM_ROUTE_ENCAP_SRV6_ENCAP_SRC_ADDR		= 2,
	FPM_ROUTE_ENCAP_SRV6_NH_RECEIVED_ID		= 3,
	FPM_ROUTE_ENCAP_SRV6_NH_ID  			= 4,
	FPM_ROUTE_ENCAP_SRV6_ENCAP_SIDLIST_NAME		= 5,
	FPM_ROUTE_ENCAP_SRV6_ENCAP_SIDLIST_LEN		= 6,
	FPM_ROUTE_ENCAP_SRV6_ENCAP_SIDLIST		= 7,
};

enum custom_rtattr_srv6_localsid_format {
	FPM_SRV6_LOCALSID_FORMAT_UNSPEC			= 0,
	FPM_SRV6_LOCALSID_FORMAT_BLOCK_LEN		= 1,
	FPM_SRV6_LOCALSID_FORMAT_NODE_LEN		= 2,
	FPM_SRV6_LOCALSID_FORMAT_FUNC_LEN		= 3,
	FPM_SRV6_LOCALSID_FORMAT_ARG_LEN		= 4,
};

enum custom_rtattr_srv6_localsid_action {
	FPM_SRV6_LOCALSID_ACTION_UNSPEC				= 0,
	FPM_SRV6_LOCALSID_ACTION_END				= 1,
	FPM_SRV6_LOCALSID_ACTION_END_X				= 2,
	FPM_SRV6_LOCALSID_ACTION_END_T				= 3,
	FPM_SRV6_LOCALSID_ACTION_END_DX2			= 4,
	FPM_SRV6_LOCALSID_ACTION_END_DX6			= 5,
	FPM_SRV6_LOCALSID_ACTION_END_DX4			= 6,
	FPM_SRV6_LOCALSID_ACTION_END_DT6			= 7,
	FPM_SRV6_LOCALSID_ACTION_END_DT4			= 8,
	FPM_SRV6_LOCALSID_ACTION_END_DT46			= 9,
	FPM_SRV6_LOCALSID_ACTION_B6_ENCAPS			= 10,
	FPM_SRV6_LOCALSID_ACTION_B6_ENCAPS_RED		= 11,
	FPM_SRV6_LOCALSID_ACTION_B6_INSERT			= 12,
	FPM_SRV6_LOCALSID_ACTION_B6_INSERT_RED		= 13,
	FPM_SRV6_LOCALSID_ACTION_UN					= 14,
	FPM_SRV6_LOCALSID_ACTION_UA					= 15,
	FPM_SRV6_LOCALSID_ACTION_UDX2				= 16,
	FPM_SRV6_LOCALSID_ACTION_UDX6				= 17,
	FPM_SRV6_LOCALSID_ACTION_UDX4				= 18,
	FPM_SRV6_LOCALSID_ACTION_UDT6				= 19,
	FPM_SRV6_LOCALSID_ACTION_UDT4				= 20,
	FPM_SRV6_LOCALSID_ACTION_UDT46				= 21,
};

enum custoem_rtattr_nexthop_group {
	FPM_NHA_JSON_STR				= 2,
};

static const char *prov_name = "dplane_fpm_sonic";

static atomic_bool fpm_cleaning_up;

struct fpm_nl_ctx {
	/* data plane connection. */
	int socket;
	bool disabled;
	bool connecting;
	bool use_nhg;
	bool use_route_replace;
	bool use_nhg_fib;
	enum fib_log_level fib_log_level;
	struct sockaddr_storage addr;

	/* data plane buffers. */
	struct stream *ibuf;
	struct stream *obuf;
	pthread_mutex_t obuf_mutex;

	/*
	 * Dplane NHG objects derived from route events (nhg-fib mode).
	 * Serialized by obuf_mutex: the tables are mutated in the same
	 * critical section that writes the resulting messages, so state
	 * changes and the byte stream they describe stay in lockstep. Two
	 * threads reach this state: the FPM pthread (normal dplane context
	 * processing) and the zebra main thread, which calls fpm_nl_enqueue()
	 * directly from the fpm_rib_send() resync walk — that is the whole
	 * locking rationale.
	 */
	struct fpm_nhg_tables nhg_tables;

	/*
	 * DELNHGFIB ids produced by contexts already written to obuf, waiting
	 * to be emitted at the HEAD of the next batch (or by the end-of-drain
	 * flush in fpm_process_queue()).
	 *
	 * Deferring them is what makes every write exactly reservable: the DEL
	 * ids only exist after fpm_nhg_unref() has already freed the objects,
	 * i.e. after the point of no return, so a context that had to emit its
	 * own DELs could never know its exact byte count before mutating. The
	 * design does not require the DELs to be in the same batch — the only
	 * invariant it needs is that a DEL arrives AFTER the route message that
	 * dereferenced it, never before. Carrying them into the next batch
	 * satisfies that strictly (see fpm_nl_enqueue_route_nhg_fib()).
	 *
	 * Serialized by obuf_mutex together with nhg_tables. Dropped without
	 * emission on reconnect: a new connection is a full resync, so the ids
	 * these DELs name no longer mean anything to the peer.
	 */
	struct fpm_nhg_del_queue pending_dels;

	/*
	 * data plane context queue:
	 * When a FPM server connection becomes a bottleneck, we must keep the
	 * data plane contexts until we get a chance to process them.
	 */
	struct dplane_ctx_list_head ctxqueue;
	pthread_mutex_t ctxqueue_mutex;

	/*
	 * Context that was dequeued but did not fit in obuf, held for retry.
	 *
	 * This is a one-slot extension of the head of ctxqueue, and exists
	 * because the dplane queue API this plugin has offers no head
	 * insertion: pushing the context back on the tail would reorder it
	 * behind later operations on the same prefix, and dropping it loses the
	 * route. It is filled and consumed only by fpm_process_queue(), which
	 * always drains it before dequeuing anything newer, so ordering is
	 * preserved with no locking of its own.
	 *
	 * Only a transient failure gets stashed. A batch larger than obuf will
	 * never fit (fpm_obuf_can_ever_fit()) and is failed to zebra instead, so
	 * this slot cannot become a permanent blockage.
	 */
	struct zebra_dplane_ctx *stashed_ctx;

	/* data plane events. */
	struct zebra_dplane_provider *prov;
	struct frr_pthread *fthread;
	struct event *t_connect;
	struct event *t_read;
	struct event *t_write;
	struct event *t_event;
	struct event *t_nhg;
	struct event *t_nhg_fib;
	struct event *t_dequeue;
	struct event *t_wedged;

	/* zebra events. */
	struct event *t_lspreset;
	struct event *t_lspwalk;
	struct event *t_nhgreset;
	struct event *t_nhgwalk;
	struct event *t_ribreset;
	struct event *t_ribwalk;
	struct event *t_rmacreset;
	struct event *t_rmacwalk;

	/* Statistic counters. */
	struct {
		/* Amount of bytes read into ibuf. */
		_Atomic uint32_t bytes_read;
		/* Amount of bytes written from obuf. */
		_Atomic uint32_t bytes_sent;
		/* Output buffer current usage. */
		_Atomic uint32_t obuf_bytes;
		/* Output buffer peak usage. */
		_Atomic uint32_t obuf_peak;

		/* Amount of connection closes. */
		_Atomic uint32_t connection_closes;
		/* Amount of connection errors. */
		_Atomic uint32_t connection_errors;

		/* Amount of user configurations: FNE_RECONNECT. */
		_Atomic uint32_t user_configures;
		/* Amount of user disable requests: FNE_DISABLE. */
		_Atomic uint32_t user_disables;

		/* Amount of data plane context processed. */
		_Atomic uint32_t dplane_contexts;
		/* Peak amount of data plane contexts enqueued. */
		_Atomic uint32_t ctxqueue_len_peak;

		/* Amount of buffer full events. */
		_Atomic uint32_t buffer_full;
	} counters;
} *gfnc;

struct seg6_iptunnel_encap_pri {
	int mode;
	char segment_name[SEG6_SEGMENT_NAME_LEN];
	struct in6_addr src;
	struct ipv6_sr_hdr srh[0];
};

enum fpm_nl_events {
	/* Ask for FPM to reconnect the external server. */
	FNE_RECONNECT,
	/* Disable FPM. */
	FNE_DISABLE,
	/* Reset counters. */
	FNE_RESET_COUNTERS,
	/* Toggle next hop group feature. */
	FNE_TOGGLE_NHG,
	/* Toggle RIB/FIB-derived next hop group feature. */
	FNE_TOGGLE_NHG_FIB,
	/* Reconnect request by our own code to avoid races. */
	FNE_INTERNAL_RECONNECT,

	/* LSP walk finished. */
	FNE_LSP_FINISHED,
	/* Next hop groups walk finished. */
	FNE_NHG_FINISHED,
	/* RIB walk finished. */
	FNE_RIB_FINISHED,
	/* RMAC walk finished. */
	FNE_RMAC_FINISHED,
};

#define FPM_RECONNECT(fnc)                                                     \
	event_add_event((fnc)->fthread->master, fpm_process_event, (fnc),     \
			 FNE_INTERNAL_RECONNECT, &(fnc)->t_event)

#define WALK_FINISH(fnc, ev)                                                   \
	event_add_event((fnc)->fthread->master, fpm_process_event, (fnc),     \
			 (ev), NULL)

/*
 * Prototypes.
 */
static void fpm_process_event(struct event *t);
static int fpm_nl_enqueue(struct fpm_nl_ctx *fnc, struct zebra_dplane_ctx *ctx);
static void fpm_lsp_send(struct event *t);
static void fpm_lsp_reset(struct event *t);
static void fpm_nhg_send(struct event *t);
static void fpm_nhg_reset(struct event *t);
static void fpm_rib_send(struct event *t);
static void fpm_rib_reset(struct event *t);
static void fpm_rmac_send(struct event *t);
static void fpm_rmac_reset(struct event *t);

/*
 * CLI.
 */
#define FPM_STR "Forwarding Plane Manager configuration\n"
DEFUN(fpm_use_route_replace, fpm_use_route_replace_cmd,
      "fpm use-route-replace",
      FPM_STR
      "Use netlink route replace semantics\n")
{
	gfnc->use_route_replace = true;
	return CMD_SUCCESS;
}

DEFUN(no_fpm_use_route_replace, no_fpm_use_route_replace_cmd,
      "no fpm use-route-replace",
      NO_STR
      FPM_STR
      "Use netlink route replace semantics\n")
{
	gfnc->use_route_replace = false;
	return CMD_SUCCESS;
}

DEFUN(fpm_set_address, fpm_set_address_cmd,
      "fpm address <A.B.C.D|X:X::X:X> [port (1-65535)]",
      FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;
	uint8_t naddr[INET6_BUFSIZ];

	if (argc == 5)
		port = strtol(argv[4]->arg, NULL, 10);

	/* Handle IPv4 addresses. */
	if (inet_pton(AF_INET, argv[2]->arg, naddr) == 1) {
		sin = (struct sockaddr_in *)&gfnc->addr;

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port =
			port ? htons(port) : htons(SOUTHBOUND_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		memcpy(&sin->sin_addr, naddr, sizeof(sin->sin_addr));

		goto ask_reconnect;
	}

	/* Handle IPv6 addresses. */
	if (inet_pton(AF_INET6, argv[2]->arg, naddr) != 1) {
		vty_out(vty, "%% Invalid address: %s\n", argv[2]->arg);
		return CMD_WARNING;
	}

	sin6 = (struct sockaddr_in6 *)&gfnc->addr;
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = port ? htons(port) : htons(SOUTHBOUND_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin6->sin6_len = sizeof(*sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	memcpy(&sin6->sin6_addr, naddr, sizeof(sin6->sin6_addr));

ask_reconnect:
	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_RECONNECT, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFUN(no_fpm_set_address, no_fpm_set_address_cmd,
      "no fpm address [<A.B.C.D|X:X::X:X> [port <1-65535>]]",
      NO_STR
      FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_DISABLE, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFUN(fpm_use_nhg, fpm_use_nhg_cmd,
      "fpm use-next-hop-groups",
      FPM_STR
      "Use netlink next hop groups feature.\n")
{
	/* Already enabled. */
	if (gfnc->use_nhg)
		return CMD_SUCCESS;

	if (gfnc->use_nhg_fib)
		vty_out(vty,
			"%% use-nhg-fib is enabled; it will be disabled by use-next-hop-groups\n");

	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_TOGGLE_NHG, &gfnc->t_nhg);

	return CMD_SUCCESS;
}

DEFUN(no_fpm_use_nhg, no_fpm_use_nhg_cmd,
      "no fpm use-next-hop-groups",
      NO_STR
      FPM_STR
      "Use netlink next hop groups feature.\n")
{
	/* Already disabled. */
	if (!gfnc->use_nhg)
		return CMD_SUCCESS;

	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_TOGGLE_NHG, &gfnc->t_nhg);

	return CMD_SUCCESS;
}

DEFUN(fpm_use_nhg_fib, fpm_use_nhg_fib_cmd,
      "fpm use-nhg-fib",
      FPM_STR
      "Derive next hop groups from route events (RIB/FIB mode).\n")
{
	/* Already enabled. */
	if (gfnc->use_nhg_fib)
		return CMD_SUCCESS;

	if (gfnc->use_nhg)
		vty_out(vty,
			"%% use-next-hop-groups is enabled; it will be disabled by use-nhg-fib\n");

	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			FNE_TOGGLE_NHG_FIB, &gfnc->t_nhg_fib);

	return CMD_SUCCESS;
}

DEFUN(no_fpm_use_nhg_fib, no_fpm_use_nhg_fib_cmd,
      "no fpm use-nhg-fib",
      NO_STR
      FPM_STR
      "Derive next hop groups from route events (RIB/FIB mode).\n")
{
	/* Already disabled. */
	if (!gfnc->use_nhg_fib)
		return CMD_SUCCESS;

	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			FNE_TOGGLE_NHG_FIB, &gfnc->t_nhg_fib);

	return CMD_SUCCESS;
}

DEFUN(fpm_set_fib_log_level, fpm_set_fib_log_level_cmd,
      "fpm fib-log-level <debug|info|warn|error>",
      FPM_STR
      "Set FIB library log level\n"
      "Debug level (most verbose)\n"
      "Info level\n"
      "Warn level\n"
      "Error level (least verbose)\n")
{
	enum fib_log_level level;
	const char *level_str = argv[2]->text;

	if (strcmp(level_str, "debug") == 0)
		level = FIB_LOG_LEVEL_DEBUG;
	else if (strcmp(level_str, "info") == 0)
		level = FIB_LOG_LEVEL_INFO;
	else if (strcmp(level_str, "warn") == 0)
		level = FIB_LOG_LEVEL_WARN;
	else if (strcmp(level_str, "error") == 0)
		level = FIB_LOG_LEVEL_ERROR;
	else {
		vty_out(vty, "%% Invalid log level: %s\n", level_str);
		return CMD_WARNING;
	}

	gfnc->fib_log_level = level;
	fib_frr_set_log_level((int)level);
	zlog_info("%s: FIB log level set to %s (%d)", __func__, level_str, (int)level);
	return CMD_SUCCESS;
}

DEFUN(no_fpm_set_fib_log_level, no_fpm_set_fib_log_level_cmd,
      "no fpm fib-log-level [<debug|info|warn|error>]",
      NO_STR
      FPM_STR
      "Set FIB library log level\n"
      "Log level value\n")
{
	gfnc->fib_log_level = FIB_LOG_LEVEL_INFO; /* restore to default: INFO */
	fib_frr_set_log_level(gfnc->fib_log_level);
	zlog_info("%s: FIB log level reset to default (INFO)", __func__);
	return CMD_SUCCESS;
}

DEFUN(fpm_reset_counters, fpm_reset_counters_cmd,
      "clear fpm counters",
      CLEAR_STR
      FPM_STR
      "FPM statistic counters\n")
{
	event_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_RESET_COUNTERS, &gfnc->t_event);
	return CMD_SUCCESS;
}

/*
 * NHG mode currently in effect. The two modes are mutually exclusive: enabling
 * one disables the other (see fpm_use_nhg / fpm_use_nhg_fib above), so a single
 * string describes the state.
 */
static const char *fpm_nhg_mode_str(const struct fpm_nl_ctx *fnc)
{
	if (fnc->use_nhg_fib)
		return "nhg-fib";
	if (fnc->use_nhg)
		return "next-hop-groups";
	return "plain";
}

DEFUN(fpm_show_status,
      fpm_show_status_cmd,
      "show fpm status [json]$json",
      SHOW_STR FPM_STR "FPM status\n" JSON_STR)
{
	struct json_object *j;
	bool connected;
	uint16_t port;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char buf[BUFSIZ];
	uint32_t nhg_live;
	uint64_t nhg_created, nhg_deleted, nhgfib_sent, nhg_dedupe_hits;

	bool json = false;
	if (argc == 4 && !strcmp(argv[3]->arg, "json")) {
		json = true;
	}
	connected = gfnc->socket > 0 ? true : false;

	switch (gfnc->addr.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)&gfnc->addr;
		snprintfrr(buf, sizeof(buf), "%pI4", &sin->sin_addr);
		port = ntohs(sin->sin_port);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&gfnc->addr;
		snprintfrr(buf, sizeof(buf), "%pI6", &sin6->sin6_addr);
		port = ntohs(sin6->sin6_port);
		break;
	default:
		strlcpy(buf, "Unknown", sizeof(buf));
		port = FPM_DEFAULT_PORT;
		break;
	}

	/*
	 * Derivation state (design D13). nhg_tables and its counters are
	 * written under obuf_mutex from two threads (the FPM pthread and the
	 * zebra main thread via the fpm_rib_send() resync walk), so this vty
	 * thread must read them holding the same mutex.
	 */
	frr_with_mutex (&gfnc->obuf_mutex) {
		nhg_live = fpm_nhg_count(&gfnc->nhg_tables);
		nhg_created = gfnc->nhg_tables.obj_created;
		nhg_deleted = gfnc->nhg_tables.obj_deleted;
		nhgfib_sent = gfnc->nhg_tables.nhgfib_sent;
		nhg_dedupe_hits = gfnc->nhg_tables.dedupe_hits;
	}

	if (json) {
		j = json_object_new_object();

		json_object_boolean_add(j, "connected", connected);
		json_object_boolean_add(j, "useNHG", gfnc->use_nhg);
		json_object_boolean_add(j, "useNHGFib", gfnc->use_nhg_fib);
		json_object_boolean_add(j, "useRouteReplace",
					gfnc->use_route_replace);
		json_object_boolean_add(j, "disabled", gfnc->disabled);
		json_object_string_add(j, "address", buf);
		json_object_int_add(j, "port", port);
		json_object_string_add(j, "nhgMode", fpm_nhg_mode_str(gfnc));
		json_object_int_add(j, "dplaneNhgLive", nhg_live);
		json_object_int_add(j, "dplaneNhgCreated", nhg_created);
		json_object_int_add(j, "dplaneNhgDeleted", nhg_deleted);
		json_object_int_add(j, "nhgFibSent", nhgfib_sent);
		json_object_int_add(j, "nhgDedupeHits", nhg_dedupe_hits);

		vty_json(vty, j);
	} else {
		struct ttable *table = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		char *out;

		ttable_rowseps(table, 0, BOTTOM, true, '-');
		ttable_add_row(table, "Address to connect to|%s", buf);
		ttable_add_row(table, "Port|%u", port);
		ttable_add_row(table, "Connected|%s", connected ? "Yes" : "No");
		ttable_add_row(table, "Use Nexthop Groups|%s",
			       gfnc->use_nhg ? "Yes" : "No");
		ttable_add_row(table, "Use NHG FIB Mode|%s",
			       gfnc->use_nhg_fib ? "Yes" : "No");
		ttable_add_row(table, "Use Route Replace Semantics|%s",
			       gfnc->use_route_replace ? "Yes" : "No");
		ttable_add_row(table, "Disabled|%s",
			       gfnc->disabled ? "Yes" : "No");
		ttable_add_row(table, "NHG Mode|%s", fpm_nhg_mode_str(gfnc));
		ttable_add_row(table, "Dplane NHG objects live|%u", nhg_live);
		ttable_add_row(table, "Dplane NHG objects created|%" PRIu64,
			       nhg_created);
		ttable_add_row(table, "Dplane NHG objects deleted|%" PRIu64,
			       nhg_deleted);
		ttable_add_row(table, "NHGFIB messages sent|%" PRIu64,
			       nhgfib_sent);
		ttable_add_row(table, "Dplane NHG dedupe hits|%" PRIu64,
			       nhg_dedupe_hits);

		out = ttable_dump(table, "\n");
		vty_out(vty, "%s\n", out);
		XFREE(MTYPE_TMP_TTABLE, out);

		ttable_del(table);
	}

	return CMD_SUCCESS;
}

DEFUN(fpm_show_counters, fpm_show_counters_cmd,
      "show fpm counters",
      SHOW_STR
      FPM_STR
      "FPM statistic counters\n")
{
	uint32_t curr_queue_len;

	frr_with_mutex (&gfnc->ctxqueue_mutex) {
		curr_queue_len = dplane_ctx_queue_count(&gfnc->ctxqueue);
	}

	vty_out(vty, "%30s\n%30s\n", "FPM counters", "============");

#define SHOW_COUNTER(label, counter) \
	vty_out(vty, "%28s: %u\n", (label), (counter))

	SHOW_COUNTER("Input bytes", gfnc->counters.bytes_read);
	SHOW_COUNTER("Output bytes", gfnc->counters.bytes_sent);
	SHOW_COUNTER("Output buffer current size", gfnc->counters.obuf_bytes);
	SHOW_COUNTER("Output buffer peak size", gfnc->counters.obuf_peak);
	SHOW_COUNTER("Connection closes", gfnc->counters.connection_closes);
	SHOW_COUNTER("Connection errors", gfnc->counters.connection_errors);
	SHOW_COUNTER("Data plane items processed",
		     gfnc->counters.dplane_contexts);
	SHOW_COUNTER("Data plane items enqueued", curr_queue_len);
	SHOW_COUNTER("Data plane items queue peak",
		     gfnc->counters.ctxqueue_len_peak);
	SHOW_COUNTER("Buffer full hits", gfnc->counters.buffer_full);
	SHOW_COUNTER("User FPM configurations", gfnc->counters.user_configures);
	SHOW_COUNTER("User FPM disable requests", gfnc->counters.user_disables);

#undef SHOW_COUNTER

	return CMD_SUCCESS;
}

DEFUN(fpm_show_counters_json, fpm_show_counters_json_cmd,
      "show fpm counters json",
      SHOW_STR
      FPM_STR
      "FPM statistic counters\n"
      JSON_STR)
{
	uint32_t curr_queue_len;

	frr_with_mutex (&gfnc->ctxqueue_mutex) {
		curr_queue_len = dplane_ctx_queue_count(&gfnc->ctxqueue);
	}

	struct json_object *jo;

	jo = json_object_new_object();
	json_object_int_add(jo, "bytes-read", gfnc->counters.bytes_read);
	json_object_int_add(jo, "bytes-sent", gfnc->counters.bytes_sent);
	json_object_int_add(jo, "obuf-bytes", gfnc->counters.obuf_bytes);
	json_object_int_add(jo, "obuf-bytes-peak", gfnc->counters.obuf_peak);
	json_object_int_add(jo, "connection-closes",
			    gfnc->counters.connection_closes);
	json_object_int_add(jo, "connection-errors",
			    gfnc->counters.connection_errors);
	json_object_int_add(jo, "data-plane-contexts",
			    gfnc->counters.dplane_contexts);
	json_object_int_add(jo, "data-plane-contexts-queue", curr_queue_len);
	json_object_int_add(jo, "data-plane-contexts-queue-peak",
			    gfnc->counters.ctxqueue_len_peak);
	json_object_int_add(jo, "buffer-full-hits", gfnc->counters.buffer_full);
	json_object_int_add(jo, "user-configures",
			    gfnc->counters.user_configures);
	json_object_int_add(jo, "user-disables", gfnc->counters.user_disables);
	vty_json(vty, jo);

	return CMD_SUCCESS;
}

/*
 * `show fpm nhg-fib` printer (design D13). One of the two output sinks is
 * active: `jarray` set means JSON, otherwise plain text goes to `vty`.
 */
struct fpm_nhg_show_args {
	struct vty *vty;
	struct json_object *jarray;
};

/* Max zebra NHG ids printed per object in the text form of `show fpm nhg-fib`. */
#define FPM_NHG_SHOW_RIB_IDS 8

static void fpm_nhg_show_obj(const struct fpm_dplane_nhg *obj, void *arg)
{
	struct fpm_nhg_show_args *sa = arg;
	struct vty *vty = sa->vty;
	char hashbuf[32];
	uint16_t i;

	snprintfrr(hashbuf, sizeof(hashbuf), "0x%016" PRIx64, obj->hash);

	if (sa->jarray) {
		struct json_object *jo = json_object_new_object();
		struct json_object *jchildren, *jrib;

		json_object_int_add(jo, "dplaneId", obj->dplane_id);
		json_object_string_add(jo, "level",
				       fpm_nhg_level_str(obj->level));
		json_object_int_add(jo, "flags", obj->nhg_flags);
		json_object_int_add(jo, "refcount", obj->refcount);
		json_object_string_add(jo, "hash", hashbuf);

		jchildren = json_object_new_array();
		for (i = 0; i < obj->num_children; i++) {
			struct json_object *jc = json_object_new_object();

			json_object_int_add(jc, "id",
					    obj->children[i].obj->dplane_id);
			json_object_int_add(jc, "weight",
					    obj->children[i].weight);
			json_object_array_add(jchildren, jc);
		}
		json_object_object_add(jo, "children", jchildren);

		/* L-B only: omitted entirely when there is no resolving info. */
		if (obj->resolved_prefix.family != AF_UNSPEC) {
			char pbuf[PREFIX_STRLEN];

			snprintfrr(pbuf, sizeof(pbuf), "%pFX",
				   &obj->resolved_prefix);
			json_object_string_add(jo, "resolvedVia", pbuf);
			json_object_int_add(jo, "resolvingRibNhgId",
					    obj->resolved_via);
		}
		json_object_int_add(jo, "vrfId", obj->vrf_id);

		jrib = json_object_new_array();
		for (i = 0; i < obj->rib_nhg_id_count; i++)
			json_object_array_add(
				jrib,
				json_object_new_int64(obj->rib_nhg_ids[i]));
		json_object_object_add(jo, "ribNhgIds", jrib);

		json_object_array_add(sa->jarray, jo);
		return;
	}

	vty_out(vty, "Dplane NHG %u (%s) flags 0x%04x refcount %u hash %s\n",
		obj->dplane_id, fpm_nhg_level_str(obj->level), obj->nhg_flags,
		obj->refcount, hashbuf);

	if (obj->resolved_prefix.family != AF_UNSPEC)
		vty_out(vty, "  resolved via %pFX vrf %u rib nhg %u\n",
			&obj->resolved_prefix, obj->vrf_id, obj->resolved_via);

	if (obj->num_children) {
		vty_out(vty, "  children:");
		for (i = 0; i < obj->num_children; i++)
			vty_out(vty, " %u(w%u)",
				obj->children[i].obj->dplane_id,
				obj->children[i].weight);
		vty_out(vty, "\n");
	}

	if (obj->rib_nhg_id_count) {
		/*
		 * The id list is uncapped (a widely shared object can collect
		 * many), so bound the text form to keep one object on one
		 * line. The json form above stays complete.
		 */
		uint16_t shown = MIN(obj->rib_nhg_id_count,
				     FPM_NHG_SHOW_RIB_IDS);

		vty_out(vty, "  rib nhg ids:");
		for (i = 0; i < shown; i++)
			vty_out(vty, " %u", obj->rib_nhg_ids[i]);
		if (shown < obj->rib_nhg_id_count)
			vty_out(vty, " +%u more",
				obj->rib_nhg_id_count - shown);
		vty_out(vty, "\n");
	}
}

/*
 * `show fpm nhg-fib resolved-via`: the inverted view of the resolving info.
 *
 * Only L-B objects carry a resolving prefix, and several of them can share one
 * (they differ in label stack or in resolved members), so the mapping is
 * prefix -> set of dplane NHG ids. That set is exactly the blast radius of the
 * prefix: when it is withdrawn, these are the objects an NHT-style repair has
 * to act on.
 *
 * Derived by walking the object table rather than from a dedicated index: the
 * view is diagnostic, so a scan cannot go stale against the objects it reports.
 */
struct fpm_nhg_rv_entry {
	struct prefix p;
	vrf_id_t vrf_id;
	uint32_t resolved_via; /* zebra NHG id of the resolution, 0 if unknown */
	uint32_t dplane_id;
};

struct fpm_nhg_rv_collect {
	struct fpm_nhg_rv_entry *ents;
	uint32_t count, cap;
};

static void fpm_nhg_rv_collect_cb(const struct fpm_dplane_nhg *obj, void *arg)
{
	struct fpm_nhg_rv_collect *c = arg;

	if (obj->resolved_prefix.family == AF_UNSPEC)
		return;

	if (c->count == c->cap) {
		c->cap = c->cap ? c->cap * 2 : 16;
		c->ents = XREALLOC(MTYPE_TMP, c->ents,
				   c->cap * sizeof(*c->ents));
	}
	c->ents[c->count].p = obj->resolved_prefix;
	c->ents[c->count].vrf_id = obj->vrf_id;
	c->ents[c->count].resolved_via = obj->resolved_via;
	c->ents[c->count].dplane_id = obj->dplane_id;
	c->count++;
}

/*
 * Group key is (vrf, prefix, resolving NHG id); dplane id only orders within a
 * group. The resolving id is part of the key so a prefix that is reached
 * through two different resolutions is reported as two rows rather than one
 * misleading merged row.
 */
static int fpm_nhg_rv_cmp(const void *a, const void *b)
{
	const struct fpm_nhg_rv_entry *ea = a, *eb = b;
	int rv;

	if (ea->vrf_id != eb->vrf_id)
		return ea->vrf_id < eb->vrf_id ? -1 : 1;
	rv = prefix_cmp(&ea->p, &eb->p);
	if (rv != 0)
		return rv;
	if (ea->resolved_via != eb->resolved_via)
		return ea->resolved_via < eb->resolved_via ? -1 : 1;
	if (ea->dplane_id != eb->dplane_id)
		return ea->dplane_id < eb->dplane_id ? -1 : 1;
	return 0;
}

static void fpm_nhg_show_resolved_via(struct vty *vty,
				      struct json_object *jarray)
{
	struct fpm_nhg_rv_collect c = {};
	char pbuf[PREFIX_STRLEN];
	uint32_t i, j, k;

	fpm_nhg_walk(&gfnc->nhg_tables, fpm_nhg_rv_collect_cb, &c);
	if (c.count == 0) {
		if (!jarray)
			vty_out(vty, "No resolving prefixes recorded\n");
		return;
	}
	qsort(c.ents, c.count, sizeof(*c.ents), fpm_nhg_rv_cmp);

	if (!jarray)
		vty_out(vty, "%-40s %-4s %-12s %s\n", "Resolving prefix",
			"VRF", "Resolved by", "Dplane NHG ids");

	for (i = 0; i < c.count; i = j) {
		/* collapse the run of entries sharing this (vrf, prefix) */
		for (j = i + 1; j < c.count; j++) {
			if (c.ents[j].vrf_id != c.ents[i].vrf_id ||
			    c.ents[j].resolved_via != c.ents[i].resolved_via ||
			    prefix_cmp(&c.ents[j].p, &c.ents[i].p) != 0)
				break;
		}

		snprintfrr(pbuf, sizeof(pbuf), "%pFX", &c.ents[i].p);

		/*
		 * Only the resolving zebra NHG id is reported. It deliberately
		 * is NOT translated through by_rib_id: that index is keyed by
		 * the id a *route* reported (dplane_ctx_get_nhe_id, i.e. the
		 * resolved NHE), and zebra_nhg_resolve() collapses several
		 * distinct NHEs onto one such id, so more than one dplane
		 * object can claim it and the index would answer with whichever
		 * recorded it last — not with the resolution.
		 */
		if (jarray) {
			struct json_object *jo = json_object_new_object();
			struct json_object *jids = json_object_new_array();

			json_object_string_add(jo, "resolvedVia", pbuf);
			json_object_int_add(jo, "vrfId", c.ents[i].vrf_id);
			json_object_int_add(jo, "resolvingRibNhgId",
					    c.ents[i].resolved_via);
			for (k = i; k < j; k++)
				json_object_array_add(
					jids,
					json_object_new_int64(
						c.ents[k].dplane_id));
			json_object_object_add(jo, "dplaneIds", jids);
			json_object_array_add(jarray, jo);
		} else {
			if (c.ents[i].resolved_via)
				vty_out(vty, "%-40s %-4u rib %-8u", pbuf,
					c.ents[i].vrf_id,
					c.ents[i].resolved_via);
			else
				vty_out(vty, "%-40s %-4u %-12s", pbuf,
					c.ents[i].vrf_id, "-");
			for (k = i; k < j; k++)
				vty_out(vty, " %u", c.ents[k].dplane_id);
			vty_out(vty, "\n");
		}
	}

	XFREE(MTYPE_TMP, c.ents);
}

/*
 * `show fpm nhg-fib route <prefix> [vrf NAME]`: the object a specific route
 * references, straight out of route_nhg_map.
 *
 * This is the only unambiguous route -> dplane id answer. Going through
 * by-rib-id instead is unsound: that index is keyed by the id a route reported
 * (dplane_ctx_get_nhe_id, i.e. the *resolved* NHE), and zebra_nhg_resolve()
 * collapses several distinct NHEs onto one such id, so two routes with
 * different trees — and therefore different dplane objects — can report the
 * same id.
 *
 * The key must be built exactly as fpm_nhg_route_key_from_ctx() does, hence
 * the table id lookup: a VRF route is keyed on that VRF's table, not on the
 * VRF id.
 */
static void fpm_nhg_show_route(struct vty *vty, struct json_object *jarray,
			       const char *prefix_str, const char *vrf_name)
{
	struct fpm_nhg_show_args sa = { .vty = vty, .jarray = jarray };
	const struct fpm_dplane_nhg *obj;
	struct fpm_nhg_route_key key;
	struct zebra_vrf *zvrf;
	struct prefix p;

	if (str2prefix(prefix_str, &p) == 0) {
		vty_out(vty, "%% Malformed prefix %s\n", prefix_str);
		return;
	}

	if (vrf_name)
		zvrf = zebra_vrf_lookup_by_name(vrf_name);
	else
		zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	if (zvrf == NULL) {
		vty_out(vty, "%% VRF %s not found\n",
			vrf_name ? vrf_name : VRF_DEFAULT_NAME);
		return;
	}

	memset(&key, 0, sizeof(key));
	key.table_id = zvrf->table_id;
	key.afi = (p.family == AF_INET6) ? AFI_IP6 : AFI_IP;
	prefix_copy(&key.p, &p);
	/* src_p stays AF_UNSPEC: srcdest routes are not addressable here. */

	obj = fpm_nhg_route_get(&gfnc->nhg_tables, &key);
	if (obj == NULL) {
		if (!jarray)
			vty_out(vty, "%% No dplane NHG for %pFX in vrf %s (table %u)\n",
				&p, vrf_name ? vrf_name : VRF_DEFAULT_NAME,
				key.table_id);
		return;
	}

	fpm_nhg_show_obj(obj, &sa);
}

DEFUN(fpm_show_nhg_fib, fpm_show_nhg_fib_cmd,
      "show fpm nhg-fib [<id (1-4294967295)|by-rib-id (1-4294967295)|resolved-via|route WORD [vrf WORD]>] [json]",
      SHOW_STR
      FPM_STR
      "Dplane next hop groups derived from route events\n"
      "Filter by dplane next hop group id\n"
      "Identifier\n"
      "Filter by zebra (rib) next hop group id\n"
      "Identifier\n"
      "Resolving prefix to dplane next hop group id mapping\n"
      "Look up the object a specific route references\n"
      "IP prefix (A.B.C.D/M or X:X::X:X/M)\n"
      VRF_CMD_HELP_STR
      "VRF name\n"
      JSON_STR)
{
	struct fpm_nhg_show_args sa = {};
	bool json = false, filter = false, rib_filter = false;
	bool resolved_via = false, found = true;
	const char *route_str = NULL, *vrf_str = NULL;
	uint32_t filter_id = 0;
	int idx;

	for (idx = 3; idx < argc; idx++) {
		if (!strcmp(argv[idx]->text, "id") && idx + 1 < argc) {
			filter = true;
			filter_id = strtoul(argv[idx + 1]->arg, NULL, 10);
			idx++;
		} else if (!strcmp(argv[idx]->text, "by-rib-id") &&
			   idx + 1 < argc) {
			rib_filter = true;
			filter_id = strtoul(argv[idx + 1]->arg, NULL, 10);
			idx++;
		} else if (!strcmp(argv[idx]->text, "resolved-via"))
			resolved_via = true;
		else if (!strcmp(argv[idx]->text, "route") && idx + 1 < argc) {
			route_str = argv[idx + 1]->arg;
			idx++;
		} else if (!strcmp(argv[idx]->text, "vrf") && idx + 1 < argc) {
			vrf_str = argv[idx + 1]->arg;
			idx++;
		} else if (!strcmp(argv[idx]->text, "json"))
			json = true;
	}

	if (gfnc == NULL || !gfnc->use_nhg_fib) {
		vty_out(vty, "FPM nhg-fib mode is not enabled\n");
		return CMD_SUCCESS;
	}

	sa.vty = vty;
	if (json)
		sa.jarray = json_object_new_array();

	/*
	 * nhg_tables is written under obuf_mutex by two threads — the FPM
	 * pthread processing dplane contexts and the zebra main thread calling
	 * fpm_nl_enqueue() from the fpm_rib_send() resync walk — together with
	 * the messages describing those mutations. A reader that skipped the
	 * mutex could see half-built objects (children array swapped in, count
	 * not yet bumped) or follow a child pointer an unref just freed, so the
	 * whole walk stays inside the same critical section.
	 */
	frr_with_mutex (&gfnc->obuf_mutex) {
		if (route_str) {
			fpm_nhg_show_route(vty, sa.jarray, route_str, vrf_str);
		} else if (resolved_via) {
			fpm_nhg_show_resolved_via(vty, sa.jarray);
		} else if (filter || rib_filter) {
			const struct fpm_dplane_nhg *obj;

			/*
			 * by-rib-id resolves through the reverse index: a zebra
			 * NHG id maps to the one dplane object its routes
			 * currently reference.
			 */
			if (rib_filter)
				obj = fpm_nhg_lookup_rib_id(&gfnc->nhg_tables,
							    filter_id);
			else
				obj = fpm_nhg_lookup_id(&gfnc->nhg_tables,
							filter_id);
			if (obj)
				fpm_nhg_show_obj(obj, &sa);
			else
				found = false;
		} else
			fpm_nhg_walk(&gfnc->nhg_tables, fpm_nhg_show_obj, &sa);
	}

	if (sa.jarray) {
		vty_json(vty, sa.jarray);
		return CMD_SUCCESS;
	}

	if (!found)
		vty_out(vty, "%% %s NHG %u not found\n",
			rib_filter ? "Rib" : "Dplane", filter_id);

	return CMD_SUCCESS;
}

static const char *fib_log_level_str(enum fib_log_level level)
{
	switch (level) {
	case FIB_LOG_LEVEL_DEBUG: return "debug";
	case FIB_LOG_LEVEL_INFO:  return "info";
	case FIB_LOG_LEVEL_WARN:  return "warn";
	case FIB_LOG_LEVEL_ERROR: return "error";
	default:                  return "unknown";
	}
}

DEFUN(fpm_show_fib_log_level, fpm_show_fib_log_level_cmd,
      "show fpm fib-log-level",
      SHOW_STR
      FPM_STR
      "Show current FIB library log level\n")
{
	vty_out(vty, "FIB log level: %d (%s)\n",
		gfnc->fib_log_level,
		fib_log_level_str(gfnc->fib_log_level));
	return CMD_SUCCESS;
}

static int fpm_write_config(struct vty *vty)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int written = 0;

	if (gfnc->disabled)
		return written;

	switch (gfnc->addr.ss_family) {
	case AF_INET:
		written = 1;
		sin = (struct sockaddr_in *)&gfnc->addr;
		vty_out(vty, "fpm address %pI4", &sin->sin_addr);
		if (sin->sin_port != htons(SOUTHBOUND_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin->sin_port));

		vty_out(vty, "\n");
		break;
	case AF_INET6:
		written = 1;
		sin6 = (struct sockaddr_in6 *)&gfnc->addr;
		vty_out(vty, "fpm address %pI6", &sin6->sin6_addr);
		if (sin6->sin6_port != htons(SOUTHBOUND_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin6->sin6_port));

		vty_out(vty, "\n");
		break;

	default:
		break;
	}

	if (!gfnc->use_nhg) {
		vty_out(vty, "no fpm use-next-hop-groups\n");
		written = 1;
	}

	if (gfnc->use_nhg_fib) {
		vty_out(vty, "fpm use-nhg-fib\n");
		written = 1;
	}

	if (!gfnc->use_route_replace) {
		vty_out(vty, "no fpm use-route-replace\n");
		written = 1;
	}

	if (gfnc->fib_log_level != FIB_LOG_LEVEL_INFO) {
		vty_out(vty, "fpm fib-log-level %s\n",
			fib_log_level_str(gfnc->fib_log_level));
		written = 1;
	}

	return written;
}

static struct cmd_node fpm_node = {
	.name = "fpm",
	.node = FPM_NODE,
	.prompt = "",
	.config_write = fpm_write_config,
};

/*
 * FPM functions.
 */
static void fpm_connect(struct event *t);

static void fpm_reconnect(struct fpm_nl_ctx *fnc)
{
	bool cleaning_p = false;

	/* This is being called in the FPM pthread: ensure we don't deadlock
	 * with similar code that may be run in the main pthread.
	 */
	if (!atomic_compare_exchange_strong_explicit(
		    &fpm_cleaning_up, &cleaning_p, true, memory_order_seq_cst,
		    memory_order_seq_cst))
		return;

	/* Cancel all zebra threads first. */
	event_cancel_async(zrouter.master, &fnc->t_lspreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_lspwalk, NULL);
	event_cancel_async(zrouter.master, &fnc->t_nhgreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_nhgwalk, NULL);
	event_cancel_async(zrouter.master, &fnc->t_ribreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_ribwalk, NULL);
	event_cancel_async(zrouter.master, &fnc->t_rmacreset, NULL);
	event_cancel_async(zrouter.master, &fnc->t_rmacwalk, NULL);

	/*
	 * Grab the lock to empty the streams (data plane might try to
	 * enqueue updates while we are closing).
	 */
	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	/* Avoid calling close on `-1`. */
	if (fnc->socket != -1) {
		close(fnc->socket);
		fnc->socket = -1;
	}

	stream_reset(fnc->ibuf);
	stream_reset(fnc->obuf);
	/*
	 * Drop all dplane NHG state: a new connection is a full resync, so
	 * no DELNHGFIB is emitted here (design §4.2.1). zebra's replay
	 * rebuilds every object with fresh ids. The deferred DELs go with it:
	 * they name ids of a connection that no longer exists.
	 */
	fpm_nhg_tables_flush(&fnc->nhg_tables);
	fpm_nhg_del_queue_reset(&fnc->pending_dels);
	event_cancel(&fnc->t_read);
	event_cancel(&fnc->t_write);

	/* Reset the barrier value */
	cleaning_p = true;
	atomic_compare_exchange_strong_explicit(
		&fpm_cleaning_up, &cleaning_p, false, memory_order_seq_cst,
		memory_order_seq_cst);

	/* FPM is disabled, don't attempt to connect. */
	if (fnc->disabled)
		return;

	event_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
			 &fnc->t_connect);
}

static void fpm_read(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	fpm_msg_hdr_t fpm;
	ssize_t rv;
	char buf[65535];
	struct nlmsghdr *hdr;
	struct zebra_dplane_ctx *ctx;
	size_t available_bytes;
	size_t hdr_available_bytes;
	int ival;
	struct dplane_ctx_list_head batch_list;

	/* Initialize the batch list */
	dplane_ctx_q_init(&batch_list);

	/* Let's ignore the input at the moment. */
	rv = stream_read_try(fnc->ibuf, fnc->socket,
			     STREAM_WRITEABLE(fnc->ibuf));
	if (rv == 0) {
		atomic_fetch_add_explicit(&fnc->counters.connection_closes, 1,
					  memory_order_relaxed);

		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: connection closed", __func__);

		FPM_RECONNECT(fnc);
		return;
	}
	if (rv == -1) {
		atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
					  memory_order_relaxed);
		zlog_warn("%s: connection failure: %s", __func__,
			  strerror(errno));
		FPM_RECONNECT(fnc);
		return;
	}

	/* Schedule the next read */
	event_add_read(fnc->fthread->master, fpm_read, fnc, fnc->socket,
			&fnc->t_read);

	/* We've got an interruption. */
	if (rv == -2)
		return;


	/* Account all bytes read. */
	atomic_fetch_add_explicit(&fnc->counters.bytes_read, rv,
				  memory_order_relaxed);

	available_bytes = STREAM_READABLE(fnc->ibuf);
	while (available_bytes) {
		if (available_bytes < (ssize_t)FPM_MSG_HDR_LEN) {
			stream_pulldown(fnc->ibuf);
			goto send_batch;
		}

		fpm.version = stream_getc(fnc->ibuf);
		fpm.msg_type = stream_getc(fnc->ibuf);
		fpm.msg_len = stream_getw(fnc->ibuf);

		if (fpm.version != FPM_PROTO_VERSION &&
		    fpm.msg_type != FPM_MSG_TYPE_NETLINK) {
			stream_reset(fnc->ibuf);
			zlog_warn(
				"%s: Received version/msg_type %u/%u, expected 1/1",
				__func__, fpm.version, fpm.msg_type);

			FPM_RECONNECT(fnc);
			goto send_batch;
		}

		/*
		 * If the passed in length doesn't even fill in the header
		 * something is wrong and reset.
		 */
		if (fpm.msg_len < FPM_MSG_HDR_LEN) {
			zlog_warn(
				"%s: Received message length: %u that does not even fill the FPM header",
				__func__, fpm.msg_len);
			FPM_RECONNECT(fnc);
			goto send_batch;
		}

		/*
		 * If we have not received the whole payload, reset the stream
		 * back to the beginning of the header and move it to the
		 * top.
		 */
		if (fpm.msg_len > available_bytes) {
			stream_rewind_getp(fnc->ibuf, FPM_MSG_HDR_LEN);
			stream_pulldown(fnc->ibuf);
			goto send_batch;
		}

		available_bytes -= FPM_MSG_HDR_LEN;

		/*
		 * Place the data from the stream into a buffer
		 */
		hdr = (struct nlmsghdr *)buf;
		stream_get(buf, fnc->ibuf, fpm.msg_len - FPM_MSG_HDR_LEN);
		hdr_available_bytes = fpm.msg_len - FPM_MSG_HDR_LEN;
		available_bytes -= hdr_available_bytes;

		if (hdr->nlmsg_len > fpm.msg_len) {
			zlog_warn(
				"%s: Received a inner header length of %u that is greater than the fpm total length of %u",
				__func__, hdr->nlmsg_len, fpm.msg_len);
			FPM_RECONNECT(fnc);
		}
		/* Not enough bytes available. */
		if (hdr->nlmsg_len > hdr_available_bytes) {
			zlog_warn(
				"%s: [seq=%u] invalid message length %u (> %zu)",
				__func__, hdr->nlmsg_seq, hdr->nlmsg_len,
				available_bytes);
			continue;
		}

		if (!(hdr->nlmsg_flags & NLM_F_REQUEST)) {
			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug(
					"%s: [seq=%u] not a request, skipping",
					__func__, hdr->nlmsg_seq);

			/*
			 * This request is a bust, go to the next one
			 */
			continue;
		}

		switch (hdr->nlmsg_type) {
		case RTM_NEWROUTE:
			/* Sanity check: need at least route msg header size. */
			if (hdr->nlmsg_len < sizeof(struct rtmsg)) {
				zlog_warn("%s: [seq=%u] invalid message length %u (< %zu)",
					  __func__, hdr->nlmsg_seq,
					  hdr->nlmsg_len, sizeof(struct rtmsg));
				break;
			}

			/*
			 * Parse the route data into a dplane ctx, add to ctx list
 			 * and enqueue the batch of ctx to zebra for processing.
 			 */
			ctx = dplane_ctx_alloc();
			dplane_ctx_route_init(ctx, DPLANE_OP_ROUTE_NOTIFY, NULL,
 					      NULL);

			if (netlink_route_notify_read_ctx(hdr, 0, ctx) >= 0) {
				/* In the FPM encoding, the vrfid is present */
				ival = dplane_ctx_get_table(ctx);
				dplane_ctx_set_vrf(ctx, ival);
				dplane_ctx_set_table(ctx,
								ZEBRA_ROUTE_TABLE_UNKNOWN);

				/* Add to the list for batching */
				dplane_ctx_enqueue_tail(&batch_list, ctx);
			} else {
				/*
				 * Let's continue to read other messages
				 * Even if we ignore this one.
				 */
				dplane_ctx_fini(&ctx);
 				stream_pulldown(fnc->ibuf);
			}
			break;
		default:
			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug(
					"%s: Received message type %u which is not currently handled",
					__func__, hdr->nlmsg_type);
			break;
		}
	}

	stream_reset(fnc->ibuf);

send_batch:
	/* Send all contexts to zebra in a single batch if we have any */
	if (dplane_ctx_queue_count(&batch_list) > 0) {
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: Sending batch of %u contexts to zebra", __func__,
				   dplane_ctx_queue_count(&batch_list));
		dplane_provider_enqueue_ctx_list_to_zebra(&batch_list);
	}
}

static void fpm_write(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	socklen_t statuslen;
	ssize_t bwritten;
	int rv, status;
	size_t btotal;

	if (fnc->connecting == true) {
		status = 0;
		statuslen = sizeof(status);

		rv = getsockopt(fnc->socket, SOL_SOCKET, SO_ERROR, &status,
				&statuslen);
		if (rv == -1 || status != 0) {
			if (rv != -1)
				zlog_warn("%s: connection failed: %s", __func__,
					  strerror(status));
			else
				zlog_warn("%s: SO_ERROR failed: %s", __func__,
					  strerror(status));

			atomic_fetch_add_explicit(
				&fnc->counters.connection_errors, 1,
				memory_order_relaxed);

			FPM_RECONNECT(fnc);
			return;
		}

		fnc->connecting = false;

		/*
		 * Starting with LSPs walk all FPM objects, marking them
		 * as unsent and then replaying them.
		 */
		event_add_timer(zrouter.master, fpm_lsp_reset, fnc, 0,
				 &fnc->t_lspreset);

		/* Permit receiving messages now. */
		event_add_read(fnc->fthread->master, fpm_read, fnc,
				fnc->socket, &fnc->t_read);
	}

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	while (true) {
		/* Stream is empty: reset pointers and return. */
		if (STREAM_READABLE(fnc->obuf) == 0) {
			stream_reset(fnc->obuf);
			break;
		}

		/* Try to write all at once. */
		btotal = stream_get_endp(fnc->obuf) -
			stream_get_getp(fnc->obuf);
		bwritten = write(fnc->socket, stream_pnt(fnc->obuf), btotal);
		if (bwritten == 0) {
			atomic_fetch_add_explicit(
				&fnc->counters.connection_closes, 1,
				memory_order_relaxed);

			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug("%s: connection closed", __func__);
			break;
		}
		if (bwritten == -1) {
			/* Attempt to continue if blocked by a signal. */
			if (errno == EINTR)
				continue;
			/* Receiver is probably slow, lets give it some time. */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			atomic_fetch_add_explicit(
				&fnc->counters.connection_errors, 1,
				memory_order_relaxed);
			zlog_warn("%s: connection failure: %s", __func__,
				  strerror(errno));

			FPM_RECONNECT(fnc);
			return;
		}

		/* Account all bytes sent. */
		atomic_fetch_add_explicit(&fnc->counters.bytes_sent, bwritten,
					  memory_order_relaxed);

		/* Account number of bytes free. */
		atomic_fetch_sub_explicit(&fnc->counters.obuf_bytes, bwritten,
					  memory_order_relaxed);

		stream_forward_getp(fnc->obuf, (size_t)bwritten);
	}

	/* Stream is not empty yet, we must schedule more writes. */
	if (STREAM_READABLE(fnc->obuf)) {
		stream_pulldown(fnc->obuf);
		event_add_write(fnc->fthread->master, fpm_write, fnc,
				 fnc->socket, &fnc->t_write);
		return;
	}
}

static void fpm_connect(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct sockaddr_in *sin = (struct sockaddr_in *)&fnc->addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&fnc->addr;
	socklen_t slen;
	int rv, sock;
	char addrstr[INET6_ADDRSTRLEN];

	sock = socket(fnc->addr.ss_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: fpm socket failed: %s", __func__,
			 strerror(errno));
		event_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
				 &fnc->t_connect);
		return;
	}

	set_nonblocking(sock);

	if (fnc->addr.ss_family == AF_INET) {
		inet_ntop(AF_INET, &sin->sin_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin);
	} else {
		inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin6);
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: attempting to connect to %s:%d", __func__,
			   addrstr, ntohs(sin->sin_port));

	rv = connect(sock, (struct sockaddr *)&fnc->addr, slen);
	if (rv == -1 && errno != EINPROGRESS) {
		atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
					  memory_order_relaxed);
		close(sock);
		zlog_warn("%s: fpm connection failed: %s", __func__,
			  strerror(errno));
		event_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
				 &fnc->t_connect);
		return;
	}

	fnc->connecting = (errno == EINPROGRESS);
	fnc->socket = sock;
	if (!fnc->connecting)
		event_add_read(fnc->fthread->master, fpm_read, fnc, sock,
				&fnc->t_read);
	event_add_write(fnc->fthread->master, fpm_write, fnc, sock,
			 &fnc->t_write);

	/*
	 * Starting with LSPs walk all FPM objects, marking them
	 * as unsent and then replaying them.
	 *
	 * If we are not connected, then delay the objects reset/send.
	 */
	if (!fnc->connecting)
		event_add_timer(zrouter.master, fpm_lsp_reset, fnc, 0,
				 &fnc->t_lspreset);
}

static struct zebra_vrf *vrf_lookup_by_table_id(uint32_t table_id)
{
 	struct vrf *vrf;
 	struct zebra_vrf *zvrf;

 	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
 		zvrf = vrf->info;
 		if (zvrf == NULL)
 			continue;
 		/* case vrf with netns : match the netnsid */
 		if (vrf_is_backend_netns()) {
 			return NULL;
 		} else {
 			/* VRF is VRF_BACKEND_VRF_LITE */
 			if (zvrf->table_id != table_id)
 				continue;
 			return zvrf;
 		}
 	}

 	return NULL;
}

static bool has_srv6_nexthop(struct zebra_dplane_ctx *ctx)
{
	struct nexthop *nexthop;

	for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop))
		if (nexthop->nh_srv6)
			return true;

	return false;
}

static bool has_srv6_sidlist_nexthop(struct zebra_dplane_ctx *ctx)
{
	struct nexthop *nexthop;

	for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop))
		if (nexthop->nh_srv6 && nexthop->nh_srv6->seg6_segs &&
		    !sid_zero(nexthop->nh_srv6->seg6_segs))
			return true;

	return false;
}

static bool has_srv6_localsid_nexthop(struct zebra_dplane_ctx *ctx)
{
	struct nexthop *nexthop;

	for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop))
		if (nexthop->nh_srv6 &&
		    nexthop->nh_srv6->seg6local_action != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
			return true;

	return false;
}

/**
 * Depth first flatten of one object's member subtree into an NHGFIB
 * nh_grp_full_list, replicating zebra_nhg_nhe2grp_full_internal()
 * (zebra/zebra_nhg.c): the node itself is never written, only its members —
 * and a member that is itself a group is written with its direct member count
 * and then immediately followed by its own (recursively flattened) members.
 *
 * fpmsyncd depends on exactly this "all depths" shape: nhgmgr.cpp
 * RIBNHGEntry::getResolvedGroupFromNHGFull() builds a NORMAL group's resolved
 * set from `if (nhg.num_direct == 0)` entries of nh_grp_full_list, so an
 * L-A group listing only its immediate L-B members would resolve to an empty
 * set and never reach the leaves that carry the actual forwarding info.
 *
 * Unlike zebra, which has no edge weight available for an inner group node
 * and writes 0 there, we write the real edge weight: the consumer only reads
 * `weight` on num_direct == 0 entries, so for inner nodes it is informational.
 *
 * \param[in] obj object whose member subtree is flattened.
 * \param[out] list nh_grp_full array to fill.
 * \param[in] max capacity of list.
 * \param[in,out] index next free slot, advanced by every entry written.
 *
 * \returns false when the subtree does not fit into max entries.
 */
static bool flatten_nhgfull_members(const struct fpm_dplane_nhg *obj,
				    struct C_nh_grp_full *list, size_t max,
				    uint32_t *index)
{
	uint16_t i;

	for (i = 0; i < obj->num_children; i++) {
		const struct fpm_dplane_nhg *child = obj->children[i].obj;

		if (*index >= max)
			return false;

		list[*index].id = child->dplane_id;
		list[*index].weight = obj->children[i].weight;
		list[*index].num_direct = child->num_children;
		(*index)++;

		/* a group member is followed by its own members */
		if (child->num_children &&
		    !flatten_nhgfull_members(child, list, max, index))
			return false;
	}

	return true;
}

/**
 * Construct a C_NextHopGroupFull object from a derived dplane NHG object.
 *
 * One builder covers all three levels of the derived hierarchy: the C object
 * shape only distinguishes "has members" (L-A / L-B, encoded by
 * libnexthopgroup's multi builder) from "is a leaf" (L-C, its singleton
 * builder), and the caller picks the encoder from obj->num_children.
 *
 * Every id on the wire is a plugin allocated uint32 dplane id (design §3.1):
 * the object's own id and every depends / nh_grp_full_list entry.
 *
 * depends[] holds the IMMEDIATE members only (what the ctx driven builder fed
 * from dplane_ctx_get_nhe_depends()), while nh_grp_full_list holds the members
 * of ALL depths, flattened depth first — see flatten_nhgfull_members().
 *
 * @param c_nhg object to fill (fully overwritten).
 * @param obj derived dplane NHG object.
 * @param grp_full_count set to the number of nh_grp_full_list entries written
 *		(the flattened member count, >= obj->num_children).
 * @return false when obj's members do not fit into the C arrays.
 */
static bool build_c_nhgfull_from_obj(struct C_NextHopGroupFull *c_nhg,
				     const struct fpm_dplane_nhg *obj,
				     uint32_t *grp_full_count)
{
	const struct nexthop *nh = obj->nh;
	uint16_t i;

	memset(c_nhg, 0, sizeof(*c_nhg));
	*grp_full_count = 0;

	/*
	 * Failing here (instead of clamping) keeps a truncated group off the
	 * wire: fpmsyncd would install it as if it were complete.
	 */
	if (obj->num_children > array_size(c_nhg->depends)) {
		zlog_err("%s: dplane NHG %u has %u members, depends[] holds %zu",
			 __func__, obj->dplane_id, obj->num_children,
			 array_size(c_nhg->depends));
		return false;
	}

	c_nhg->id = obj->dplane_id;
	/*
	 * The JSON `key` is 32 bit and purely informational (it used to carry
	 * zebra's NHG hash): the low half of the Merkle hash is the closest
	 * equivalent. Nothing keys off the wire value — the plugin dedupes on
	 * the full 64 bit hash, fpmsyncd on the id.
	 */
	c_nhg->key = (uint32_t)obj->hash;
	c_nhg->nhg_flags = obj->nhg_flags;

	/* depends[]: immediate members only */
	for (i = 0; i < obj->num_children; i++)
		c_nhg->depends[i] = obj->children[i].obj->dplane_id;

	/* nh_grp_full_list: members of all depths, flattened depth first */
	if (!flatten_nhgfull_members(obj, c_nhg->nh_grp_full_list,
				     array_size(c_nhg->nh_grp_full_list),
				     grp_full_count)) {
		zlog_err("%s: dplane NHG %u member tree overflows the %zu entry nh_grp_full_list",
			 __func__, obj->dplane_id,
			 array_size(c_nhg->nh_grp_full_list));
		return false;
	}

	/*
	 * dependents[] stays empty (the memset above): fpmsyncd derives the
	 * reverse edges from the depends lists it registers (design §4.2.1).
	 */

	/*
	 * Nexthop detail fields, same set the ctx driven singleton builder
	 * used to emit. A leaf (L-C) has its own nexthop, a resolved group
	 * (L-B) has its recursive parent — which is what the old multi builder
	 * took gate/type from — and an L-A group has no defining nexthop.
	 */
	if (nh) {
		c_nhg->type = nh->type;
		c_nhg->vrf_id = nh->vrf_id;
		c_nhg->ifindex = nh->ifindex;
		c_nhg->nh_label_type = nh->nh_label_type;

		if (nh->type == NEXTHOP_TYPE_BLACKHOLE)
			c_nhg->bh_type = nh->bh_type;
		else
			memcpy(&c_nhg->gate, &nh->gate, sizeof(union g_addr));

		memcpy(&c_nhg->src, &nh->src, sizeof(union g_addr));
		memcpy(&c_nhg->rmap_src, &nh->rmap_src, sizeof(union g_addr));
		c_nhg->weight = nh->weight;
		c_nhg->flags = nh->flags;

		/*
		 * set nexthop srv6 information if present. A nexthop_srv6 that
		 * carries neither a segment list nor a seg6local action holds
		 * nothing the peer can use (nhgmgr.cpp getNextHopFields() only
		 * reads nh_srv6 when nh_srv6->seg6_segs is non null), so do not
		 * allocate one for it.
		 */
		if (nh->nh_srv6 != NULL &&
		    (nh->nh_srv6->seg6_segs != NULL ||
		     nh->nh_srv6->seg6local_action !=
			     ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)) {
			/* Get the default SRv6 context which contains seg6's src IP */
			struct zebra_srv6 *srv6 = zebra_srv6_get_default();

			c_nhg->nh_srv6 = malloc(sizeof(struct C_nexthop_srv6));
			if (c_nhg->nh_srv6) {
				/* field copy from nexthop_srv6 to C_nexthop_srv6 */
				/* seg6local_action */
				c_nhg->nh_srv6->seg6local_action =
					(enum C_seg6local_action_t)nh->nh_srv6->seg6local_action;

				/* seg6local_ctx */
				memcpy(&c_nhg->nh_srv6->seg6local_ctx, &nh->nh_srv6->seg6local_ctx,
					sizeof(struct C_seg6local_context));

				/* seg6_src */
				c_nhg->nh_srv6->seg6_src = srv6->encap_src_addr;

				/* seg6_segs */
				c_nhg->nh_srv6->seg6_segs = NULL;  // clear the pointer to avoid pointing to old address
				/* set nexthop_srv6 seg6_segs if present */
				if (nh->nh_srv6->seg6_segs != NULL) {
					size_t total_size = sizeof(struct C_seg6_seg_stack) +
								nh->nh_srv6->seg6_segs->num_segs * sizeof(struct in6_addr);
					c_nhg->nh_srv6->seg6_segs = malloc(total_size);
					if (c_nhg->nh_srv6->seg6_segs) {
						memcpy(c_nhg->nh_srv6->seg6_segs, nh->nh_srv6->seg6_segs, total_size);
					}
				}
			}
		}
	}

	/*
	 * obj->resolved_prefix / obj->vrf_id (L-B resolving info) are
	 * deliberately NOT emitted: they are plugin internal state feeding the
	 * dedupe hash and the future binding table (design D3). The NHGFIB
	 * schema has no field for them and fpmsyncd never reads them.
	 */

	return true;
}

/**
 * Free C_NextHopGroupFull Object.
 *
 * \param[in] c_nhg pointer of C_NextHopGroupFull Object.
 */
static void free_c_nexthopgroupfull(struct C_NextHopGroupFull *c_nhg)
{
	if (!c_nhg) {
		return;
	}

	/* Free srv6 related memory if present */
	if (c_nhg->nh_srv6) {
		/* Free seg6_segs if present */
		if (c_nhg->nh_srv6->seg6_segs) {
			free(c_nhg->nh_srv6->seg6_segs);
			c_nhg->nh_srv6->seg6_segs = NULL;
		}

		/* Free nh_srv6 itself */
		free(c_nhg->nh_srv6);
		c_nhg->nh_srv6 = NULL;
	}
}

/**
 * Resets the SRv6 routes FPM flags so we send all SRv6 routes again.
 */
static void fpm_srv6_route_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_entry *re;
	struct route_table *rt;
	struct nexthop *nexthop;
	rib_tables_iter_t rt_iter;

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			dest = rib_dest_from_rnode(rn);
			/* Skip bad route entries. */
			if (dest == NULL)
				continue;

			re = dest->selected_fib;
			if (re == NULL)
				continue;

			nexthop = re->nhe->nhg.nexthop;
			if (nexthop && nexthop->nh_srv6 &&
					!sid_zero((const struct seg6_seg_stack *)nexthop->nh_srv6->seg6_segs))
				/* Unset FPM installation flag so it gets installed again. */
				UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		}
	}

	/* Schedule next step: send RIB routes. */
	event_add_event(zrouter.master, fpm_rib_send, fnc, 0, &fnc->t_ribwalk);
}

/*
 * SRv6 localsid change via netlink interface, using a dataplane context object
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
static ssize_t netlink_srv6_localsid_msg_encode(int cmd,
					   struct zebra_dplane_ctx *ctx,
					   uint8_t *data, size_t datalen,
					   bool fpm, bool force_nhg)
{
	struct zebra_srv6 *srv6 = zebra_srv6_get_default();
	struct zebra_vrf *zvrf;
	struct listnode *node;
	struct rtattr *nest;
	const struct seg6local_context *seg6local_ctx;
	struct nexthop *nexthop;
	const struct prefix *p;
	struct nlsock *nl;
	int bytelen;
	vrf_id_t vrf_id;
	uint32_t table_id;
	uint32_t action;
	uint32_t block_len, node_len, func_len, arg_len;
	bool is_usid = false;
	struct interface *ifp;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[];
	} *req = (void *)data;

	nexthop = dplane_ctx_get_ng(ctx)->nexthop;
	if (!nexthop || !nexthop->nh_srv6 || nexthop->nh_srv6->seg6local_action == ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
		return -1;

	p = dplane_ctx_get_dest(ctx);

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	if (p->family != AF_INET6) {
		zlog_err("%s: invalid family: expected %u, got %u", __func__, AF_INET6, p->family);
		return -1;
	}

	bytelen = IPV6_MAX_BYTELEN;

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if ((cmd == RTM_NEWSRV6LOCALSID) &&
		(zrouter.zav.v6_rr_semantics))
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->r.rtm_family = p->family;
	req->r.rtm_dst_len = p->prefixlen;
	req->r.rtm_scope = RT_SCOPE_UNIVERSE;
	req->r.rtm_type = RTN_UNICAST;

	if (cmd == RTM_DELSRV6LOCALSID)
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_old_type(ctx));
	else
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_type(ctx));

	if (!nl_attr_put(&req->n, datalen, FPM_SRV6_LOCALSID_SID_VALUE, &p->u.prefix, bytelen))
		return 0;

	/*
	 * Also emit standard RTA_DST so fpmsyncd's offload-ack (which
	 * rewrites nlmsg_type to RTM_NEWROUTE and echoes the body back)
	 * can be parsed by zebra's regular route reader.
	 */
	if (!nl_attr_put(&req->n, datalen, RTA_DST, &p->u.prefix, bytelen))
		return 0;

	/* Table corresponding to this route. */
	table_id = dplane_ctx_get_table(ctx);
	if (!fpm) {
		if (table_id < 256)
			req->r.rtm_table = table_id;
		else {
			req->r.rtm_table = RT_TABLE_UNSPEC;
			if (!nl_attr_put32(&req->n, datalen, RTA_TABLE, table_id))
				return 0;
		}
	} else {
		/* Put vrf if_index instead of table id */
		vrf_id = dplane_ctx_get_vrf(ctx);
		if (vrf_id < 256)
			req->r.rtm_table = vrf_id;
		else {
			req->r.rtm_table = RT_TABLE_UNSPEC;
			if (!nl_attr_put32(&req->n, datalen, RTA_TABLE, vrf_id))
				return 0;
		}
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug(
			"%s: %s %pFX vrf %u(%u)", __func__,
			(cmd == RTM_NEWSRV6LOCALSID) ? "RTM_NEWSRV6LOCALSID" : "RTM_DELSRV6LOCALSID", p, dplane_ctx_get_vrf(ctx),
			table_id);

	seg6local_ctx = &nexthop->nh_srv6->seg6local_ctx;

	nest =
		nl_attr_nest(&req->n, datalen, 
					FPM_SRV6_LOCALSID_FORMAT);

	block_len = nexthop->nh_srv6->seg6local_ctx.block_len;
	node_len = nexthop->nh_srv6->seg6local_ctx.node_len;
	func_len = nexthop->nh_srv6->seg6local_ctx.function_len;
	arg_len = nexthop->nh_srv6->seg6local_ctx.argument_len;

	/*
	 * If block/node/func/arg length are not provided by the srv6 nexthop,
	 * then we use the default values
	 */
	if (block_len == 0 && node_len == 0 && func_len == 0 && arg_len == 0) {
		block_len = DEFAULT_SRV6_LOCALSID_FORMAT_BLOCK_LEN;
		node_len = DEFAULT_SRV6_LOCALSID_FORMAT_NODE_LEN;
		func_len = DEFAULT_SRV6_LOCALSID_FORMAT_FUNCTION_LEN;
		arg_len = DEFAULT_SRV6_LOCALSID_FORMAT_ARGUMENT_LEN;
	}

	if (!nl_attr_put8(
			&req->n, datalen, 
			FPM_SRV6_LOCALSID_FORMAT_BLOCK_LEN,
			block_len))
		return -1;

	if (!nl_attr_put8(
			&req->n, datalen, 
			FPM_SRV6_LOCALSID_FORMAT_NODE_LEN,
			node_len))
		return -1;

	if (!nl_attr_put8(
			&req->n, datalen, 
			FPM_SRV6_LOCALSID_FORMAT_FUNC_LEN,
			func_len))
		return -1;

	if (!nl_attr_put8(
			&req->n, datalen, 
			FPM_SRV6_LOCALSID_FORMAT_ARG_LEN,
			arg_len))
		return -1;

	nl_attr_nest_end(&req->n, nest);

	if (cmd == RTM_DELSRV6LOCALSID)
		return NLMSG_ALIGN(req->n.nlmsg_len);

	is_usid = CHECK_SRV6_FLV_OP(nexthop->nh_srv6->seg6local_ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);

	switch (nexthop->nh_srv6->seg6local_action) {
	case ZEBRA_SEG6_LOCAL_ACTION_END:
		action = is_usid ? FPM_SRV6_LOCALSID_ACTION_UN : FPM_SRV6_LOCALSID_ACTION_END;
		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					action))
			return -1;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_X:
		action = is_usid ? FPM_SRV6_LOCALSID_ACTION_UA : FPM_SRV6_LOCALSID_ACTION_END_X;
		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					action))
			return -1;
		if (!nl_attr_put(&req->n, datalen, 
					FPM_SRV6_LOCALSID_NH6, &seg6local_ctx->nh6,
					sizeof(struct in6_addr)))
			return -1;

		ifp = if_lookup_by_index(seg6local_ctx->ifindex, VRF_DEFAULT);
		if (ifp)
			if (!nl_attr_put(&req->n, datalen,
					FPM_SRV6_LOCALSID_IFNAME, ifp->name,
					strlen(ifp->name) + 1))
			return -1;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_T:
		zvrf = vrf_lookup_by_table_id(seg6local_ctx->table);
		if (!zvrf)
			return false;

		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					FPM_SRV6_LOCALSID_ACTION_END_T))
			return -1;
		if (!nl_attr_put(&req->n, datalen, 
					FPM_SRV6_LOCALSID_VRFNAME,
					zvrf->vrf->name,
					strlen(zvrf->vrf->name) + 1))
			return -1;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
		action = is_usid ? FPM_SRV6_LOCALSID_ACTION_UDX6 : FPM_SRV6_LOCALSID_ACTION_END_DX6;
		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					action))
			return -1;
		if (!nl_attr_put(&req->n, datalen, 
					FPM_SRV6_LOCALSID_NH6, &seg6local_ctx->nh6,
					sizeof(struct in6_addr)))
			return -1;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
		action = is_usid ? FPM_SRV6_LOCALSID_ACTION_UDX4 : FPM_SRV6_LOCALSID_ACTION_END_DX4;
		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					action))
			return -1;
		if (!nl_attr_put(&req->n, datalen, 
					FPM_SRV6_LOCALSID_NH4, &seg6local_ctx->nh4,
					sizeof(struct in_addr)))
			return -1;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
		zvrf = vrf_lookup_by_table_id(seg6local_ctx->table);
		if (!zvrf)
			return false;

		action = is_usid ? FPM_SRV6_LOCALSID_ACTION_UDT6 : FPM_SRV6_LOCALSID_ACTION_END_DT6;
		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					action))
			return -1;
		if (!nl_attr_put(&req->n, datalen, 
					FPM_SRV6_LOCALSID_VRFNAME,
					zvrf->vrf->name,
					strlen(zvrf->vrf->name) + 1))
			return -1;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
		zvrf = vrf_lookup_by_table_id(seg6local_ctx->table);
		if (!zvrf)
			return false;

		action = is_usid ? FPM_SRV6_LOCALSID_ACTION_UDT4 : FPM_SRV6_LOCALSID_ACTION_END_DT4;
		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					action))
			return -1;
		if (!nl_attr_put(&req->n, datalen, 
					FPM_SRV6_LOCALSID_VRFNAME,
					zvrf->vrf->name,
					strlen(zvrf->vrf->name) + 1))
			return -1;
		break;
	case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
		zvrf = vrf_lookup_by_table_id(seg6local_ctx->table);
		if (!zvrf)
			return false;

		action = is_usid ? FPM_SRV6_LOCALSID_ACTION_UDT46 : FPM_SRV6_LOCALSID_ACTION_END_DT46;
		if (!nl_attr_put32(&req->n, datalen, 
					FPM_SRV6_LOCALSID_ACTION,
					action))
			return -1;
		if (!nl_attr_put(&req->n, datalen, 
					FPM_SRV6_LOCALSID_VRFNAME,
					zvrf->vrf->name,
					strlen(zvrf->vrf->name) + 1))
			return -1;
		break;
	default:
		zlog_err("%s: unsupport seg6local behaviour action=%u",
				__func__,
				nexthop->nh_srv6->seg6local_action);
		return -1;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}
/*
 * SRv6 VPN route change via netlink interface (use nhg) , using a dataplane context object
 *
 * The two NHG ids come from the caller: in nhg-fib mode they are the plugin
 * allocated dplane ids of the derived objects (design §3.2), which is what
 * fpmsyncd resolves against the NHGFIB stream. There is no zebra getter for a
 * "received" NHG id on the upstream base.
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
static ssize_t netlink_vpn_route_msg_encode(int cmd,
					   struct zebra_dplane_ctx *ctx,
					   uint8_t *data, size_t datalen,
					   uint32_t nhg_received_id, uint32_t nhg_id)
{
	struct rtattr *nest;
	struct nexthop *nexthop;
	const struct prefix *p;
	struct nlsock *nl;
	int bytelen;
	vrf_id_t vrf_id;
	uint32_t table_id;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[];
	} *req = (void *)data;

	nexthop = dplane_ctx_get_ng(ctx)->nexthop;
	if (!nexthop || !nexthop->nh_srv6 || sid_zero(nexthop->nh_srv6->seg6_segs))
		return -1;

	p = dplane_ctx_get_dest(ctx);

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	bytelen = (p->family == AF_INET ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if ((cmd == RTM_NEWROUTE) &&
	    ((p->family == AF_INET) || zrouter.zav.v6_rr_semantics))
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	if(cmd == RTM_NEWROUTE)
		cmd =RTM_NEWSRV6VPNROUTE;
	else
		cmd = RTM_DELSRV6VPNROUTE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->r.rtm_family = p->family;
	req->r.rtm_dst_len = p->prefixlen;
	req->r.rtm_scope = RT_SCOPE_UNIVERSE;

	if (cmd == RTM_DELSRV6VPNROUTE)
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_old_type(ctx));
	else
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_type(ctx));

	req->r.rtm_type = RTN_UNICAST;

	if (!nl_attr_put(&req->n, datalen, RTA_DST, &p->u.prefix, bytelen))
		return 0;

	/* Table corresponding to this route. */
	table_id = dplane_ctx_get_table(ctx);
	/* Put vrf if_index instead of table id */
	vrf_id = dplane_ctx_get_vrf(ctx);
	if (vrf_id < 256)
		req->r.rtm_table = vrf_id;
	else {
		req->r.rtm_table = RT_TABLE_UNSPEC;
		if (!nl_attr_put32(&req->n, datalen, RTA_TABLE, vrf_id))
			return 0;
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug(
			"%s: %s %pFX vrf %u(%u)", __func__,
			nl_msg_type_to_str(cmd), p, dplane_ctx_get_vrf(ctx),
			table_id);

	if (!nl_attr_put16(&req->n, datalen, RTA_ENCAP_TYPE,
				FPM_ROUTE_ENCAP_SRV6))
		return false;
	nest = nl_attr_nest(&req->n, datalen, RTA_ENCAP);
	if (!nest)
		return false;

    if (!nl_attr_put32(&req->n, datalen, FPM_ROUTE_ENCAP_SRV6_NH_RECEIVED_ID, nhg_received_id)){
		return 0;
	}

	if (!nl_attr_put32(&req->n, datalen, FPM_ROUTE_ENCAP_SRV6_NH_ID, nhg_id)){
		return 0;
	}

	nl_attr_nest_end(&req->n, nest);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static bool netlink_srv6_vpn_route_msg_encode_multipath(int cmd, struct zebra_dplane_ctx *ctx,
							uint8_t *data, size_t datalen,
							const struct nexthop *nexthop,
							struct nlmsghdr *nlmsg, size_t req_size,
							bool fpm, bool force_nhg)
{
	struct rtattr *nest;
	struct rtnexthop *rtnh;
	struct interface *ifp;
	struct in6_addr encap_src_addr = {};
	struct connected *connected;
	struct vrf *vrf;
	struct prefix *cp;

	rtnh = nl_attr_rtnh(nlmsg, req_size);
	if (rtnh == NULL)
		return false;

	if (!nl_attr_put16(nlmsg, req_size, RTA_ENCAP_TYPE, FPM_ROUTE_ENCAP_SRV6))
		return false;

	nest = nl_attr_nest(nlmsg, req_size, RTA_ENCAP);
	if (!nest)
		return false;

	/*
     * by default, we use the loopback address as encap source address,
     * if it is valid
     */
	ifp = if_lookup_by_name("lo", VRF_DEFAULT);

	if (ifp) {
		vrf = vrf_lookup_by_name(VRF_DEFAULT_NAME);
		if (!vrf)
			return false;

		FOR_ALL_INTERFACES (vrf, ifp) {
			frr_each (if_connected, ifp->connected, connected) {
				cp = connected->address;
				if (cp->family == AF_INET6 &&
				    !IN6_IS_ADDR_LOOPBACK(&cp->u.prefix6) &&
				    !IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6)) {
					encap_src_addr = cp->u.prefix6;
					break;
				}
			}
		}
	}

	if (!nl_attr_put(nlmsg, req_size, FPM_ROUTE_ENCAP_SRV6_ENCAP_SRC_ADDR, &encap_src_addr,
			 IPV6_MAX_BYTELEN))
		return false;

	if (!nl_attr_put(nlmsg, req_size, FPM_ROUTE_ENCAP_SRV6_VPN_SID,
			 &nexthop->nh_srv6->seg6_segs->seg[0], IPV6_MAX_BYTELEN))
		return false;

	nl_attr_nest_end(nlmsg, nest);

	nl_attr_rtnh_end(nlmsg, rtnh);

	return true;
}

/*
 * SRv6 VPN route change via netlink interface, using a dataplane context object
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
static ssize_t netlink_srv6_vpn_route_msg_encode(int cmd,
					   struct zebra_dplane_ctx *ctx,
					   uint8_t *data, size_t datalen,
					   bool fpm, bool force_nhg)
{
	struct rtattr *nest;
	struct nexthop *nexthop;
	const struct prefix *p;
	struct nlsock *nl;
	int bytelen;
	vrf_id_t vrf_id;
	uint32_t table_id;
	struct interface *ifp;
	struct in6_addr encap_src_addr = {};
	struct connected *connected;
	struct vrf *vrf;
	struct prefix *cp;
	unsigned int nexthop_num;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[];
	} *req = (void *)data;

	p = dplane_ctx_get_dest(ctx);

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	bytelen = (p->family == AF_INET ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if ((cmd == RTM_NEWROUTE) &&
		((p->family == AF_INET) || zrouter.zav.v6_rr_semantics))
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->r.rtm_family = p->family;
	req->r.rtm_dst_len = p->prefixlen;
	req->r.rtm_scope = RT_SCOPE_UNIVERSE;

	if (cmd == RTM_DELROUTE)
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_old_type(ctx));
	else
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_type(ctx));

	req->r.rtm_type = RTN_UNICAST;

	if (!nl_attr_put(&req->n, datalen, RTA_DST, &p->u.prefix, bytelen))
		return 0;

	/* Table corresponding to this route. */
	table_id = dplane_ctx_get_table(ctx);
	if (!fpm) {
		if (table_id < 256)
			req->r.rtm_table = table_id;
		else {
			req->r.rtm_table = RT_TABLE_UNSPEC;
			if (!nl_attr_put32(&req->n, datalen, RTA_TABLE, table_id))
				return 0;
		}
	} else {
		/* Put vrf if_index instead of table id */
		vrf_id = dplane_ctx_get_vrf(ctx);
		if (vrf_id < 256)
			req->r.rtm_table = vrf_id;
		else {
			req->r.rtm_table = RT_TABLE_UNSPEC;
			if (!nl_attr_put32(&req->n, datalen, RTA_TABLE, vrf_id))
				return 0;
		}
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug(
			"%s: %s %pFX vrf %u(%u)", __func__,
			nl_msg_type_to_str(cmd), p, dplane_ctx_get_vrf(ctx),
			table_id);

	/*
	 * Counts the number of nexthops to determine if the route is singlepath
	 * (single nexthop) or multipath (multiple nexthops)
	 */
	nexthop_num = 0;
	for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;
		if (!NEXTHOP_IS_ACTIVE(nexthop->flags))
			continue;

		nexthop_num++;
	}

	/* Multipath case */
	if (nexthop_num > 1) {
		struct rtattr *nest;

		nest = nl_attr_nest(&req->n, datalen, RTA_MULTIPATH);
		if (nest == NULL)
			return 0;

		nexthop_num = 0;
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			/* Skip non-SRv6 nexthops */
			if (!nexthop->nh_srv6 || sid_zero(nexthop->nh_srv6->seg6_segs))
				continue;

			if (NEXTHOP_IS_ACTIVE(nexthop->flags)) {
				nexthop_num++;

				if (!netlink_srv6_vpn_route_msg_encode_multipath(cmd, ctx, data,
										 datalen, nexthop,
										 &req->n, datalen,
										 fpm, force_nhg))
					return 0;
			}
		}

		nl_attr_nest_end(&req->n, nest);

		if (nexthop_num == 0) {
			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug("%s: No useful nexthop.", __func__);
		}

		return NLMSG_ALIGN(req->n.nlmsg_len);
	}

	/* Singlepath case */
	nexthop_num = 0;
	for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;
		if (!NEXTHOP_IS_ACTIVE(nexthop->flags))
			continue;
		if (!nexthop->nh_srv6 || sid_zero(nexthop->nh_srv6->seg6_segs))
			continue;

		nexthop_num++;
		break;
	}

	if (nexthop_num == 0) {
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: No useful nexthop.", __func__);

		return NLMSG_ALIGN(req->n.nlmsg_len);
	}

	if (!nl_attr_put16(&req->n, datalen, RTA_ENCAP_TYPE,
				FPM_ROUTE_ENCAP_SRV6))
		return false;
	nest = nl_attr_nest(&req->n, datalen, RTA_ENCAP);
	if (!nest)
		return false;

	/*
	 * by default, we use the loopback address as encap source address,
	 * if it is valid
	 */
	ifp = if_lookup_by_name("lo", VRF_DEFAULT);
	vrf = vrf_lookup_by_name(VRF_DEFAULT_NAME);
	if (!vrf)
		return false;
	if (ifp) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			frr_each (if_connected, ifp->connected, connected) {
				cp = connected->address;
				if (cp->family == AF_INET6 &&
						!IN6_IS_ADDR_LOOPBACK(&cp->u.prefix6) &&
						!IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6)) {
					encap_src_addr = cp->u.prefix6;
					break;
				}
			}
		}
	}

	if (!nl_attr_put(
			&req->n, datalen, FPM_ROUTE_ENCAP_SRV6_ENCAP_SRC_ADDR,
			&encap_src_addr, IPV6_MAX_BYTELEN))
		return false;
	if (!nl_attr_put(&req->n, datalen, FPM_ROUTE_ENCAP_SRV6_VPN_SID,
				&nexthop->nh_srv6->seg6_segs->seg[0],
				IPV6_MAX_BYTELEN))
		return false;
	nl_attr_nest_end(&req->n, nest);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/*
 * SRv6 change via netlink interface, using a dataplane context object
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
static ssize_t netlink_srv6_msg_encode(int cmd,
					   struct zebra_dplane_ctx *ctx,
					   uint8_t *data, size_t datalen,
					   bool fpm, bool force_nhg)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[];
	} *req = (void *)data;

	if (!has_srv6_nexthop(ctx))
		return -1;

	if (has_srv6_localsid_nexthop(ctx)) {
		if (cmd == RTM_NEWROUTE)
			cmd = RTM_NEWSRV6LOCALSID;
		else if (cmd == RTM_DELROUTE)
			cmd = RTM_DELSRV6LOCALSID;

		if (!netlink_srv6_localsid_msg_encode(
				cmd, ctx, data, datalen, fpm, force_nhg))
			return 0;
	} else if (has_srv6_sidlist_nexthop(ctx)) {
		/*
		 * Legacy (non nhg-fib) modes publish no NHGFIB objects, so the
		 * id carrying RTM_NEWSRV6VPNROUTE encode has nothing for
		 * fpmsyncd to resolve: always emit the per-nexthop SRv6 encap
		 * form here. The id form lives on the nhg-fib path, which owns
		 * the ids (design §3.2).
		 */
		if (!netlink_srv6_vpn_route_msg_encode(
			cmd, ctx, data, datalen, fpm, force_nhg))
			return 0;
	} else {
		zlog_err(
			"%s: invalid srv6 nexthop", __func__);
		return -1;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/**
 * Encode one RTM_NEWNHGFIB message for a derived dplane NHG object.
 *
 * Same wire shape the ctx driven encoder produced (nhmsg + NHA_ID +
 * FPM_NHA_JSON_STR holding the C_NextHopGroupFull JSON), with every id taken
 * from the derived objects instead of the fork's NHG-event ctx getters. The
 * JSON itself is still produced by libnexthopgroup: the multi builder for an
 * object with members, the singleton builder for a leaf.
 *
 * There is no ctx here (an object outlives the ctx that created it), so
 * nlmsg_pid stays 0 — fpmsyncd only looks at nlmsg_type and the attributes.
 *
 * \param[in] obj derived dplane NHG object.
 * \param[out] buf buffer to hold the packet.
 * \param[in] buflen amount of buffer bytes.
 *
 * \returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
static ssize_t netlink_nhgfib_obj_msg_encode(const struct fpm_dplane_nhg *obj,
					     void *buf, size_t buflen)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
		char buf[];
	} *req = buf;

	struct C_NextHopGroupFull c_nhg;
	uint32_t grp_full_count = 0;
	char *json_str = NULL;
	ssize_t ret = -1;

	if (buflen < sizeof(*req))
		return 0;

	if (!build_c_nhgfull_from_obj(&c_nhg, obj, &grp_full_count)) {
		free_c_nexthopgroupfull(&c_nhg);
		return -1;
	}

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_REPLACE;
	req->n.nlmsg_type = RTM_NEWNHGFIB;

	req->nhm.nh_family = AF_UNSPEC;

	/* Put the dplane NHG id */
	if (!nl_attr_put32(&req->n, buflen, NHA_ID, obj->dplane_id)) {
		free_c_nexthopgroupfull(&c_nhg);
		return 0;
	}

	if (obj->num_children) {
		/*
		 * Group (L-A top level set or L-B resolved set).
		 * nh_grp_full_list is the all depths flattened member list
		 * (grp_full_count entries), depends[] the immediate members.
		 * The recursive form additionally carries the resolving
		 * nexthop's gate/type, which only an L-B object has.
		 */
		json_str = nexthopgroupfull_json_from_c_nhg_multi(
			&c_nhg, grp_full_count, obj->num_children, 0,
			CHECK_FLAG(obj->nhg_flags, FPM_NHG_FLAG_RECURSIVE));
	} else {
		/*
		 * Leaf (L-C). nh_family used to come from the NHG event's afi;
		 * derive it from the nexthop instead and leave it AF_UNSPEC
		 * when the nexthop is not address typed.
		 */
		switch (c_nhg.type) {
		case C_NEXTHOP_TYPE_IPV4:
		case C_NEXTHOP_TYPE_IPV4_IFINDEX:
			req->nhm.nh_family = AF_INET;
			break;
		case C_NEXTHOP_TYPE_IPV6:
		case C_NEXTHOP_TYPE_IPV6_IFINDEX:
			req->nhm.nh_family = AF_INET6;
			break;
		default:
			break;
		}

		json_str = nexthopgroupfull_json_from_c_nhg_singleton(&c_nhg, 0, 0);
	}

	if (!json_str) {
		zlog_err("%s: failed to convert dplane NHG %u to a JSON string",
			 __func__, obj->dplane_id);
		free_c_nexthopgroupfull(&c_nhg);
		return -1;
	}

	/* Encode JSON string as attribute in message */
	if (!nl_attr_put(&req->n, buflen, FPM_NHA_JSON_STR, json_str,
			 strlen(json_str) + 1)) {
		zlog_err("%s: dplane NHG %u JSON (%zu bytes) does not fit the message",
			 __func__, obj->dplane_id, strlen(json_str) + 1);
		goto cleanup;
	}

	ret = NLMSG_ALIGN(req->n.nlmsg_len);

	/*
	 * The FPM header carries the frame length as a u16 (stream_putw()), so
	 * a frame that cannot be framed must never reach the batch — where it
	 * would trip an assert. buflen alone does not guarantee it: the scratch
	 * buffer is DPLANE_FPM_NL_BUF_SIZE (64KiB), slightly more than the
	 * framing allows once the header is added.
	 */
	if ((size_t)ret + FPM_HEADER_SIZE > UINT16_MAX) {
		zlog_err("%s: dplane NHG %u message is %zd bytes, too large to frame",
			 __func__, obj->dplane_id, ret);
		ret = -1;
	}

cleanup:
	free(json_str);
	free_c_nexthopgroupfull(&c_nhg);

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: RTM_NEWNHGFIB, id=%u, len=%zd", __func__,
			   obj->dplane_id, ret);

	return ret;
}

/**
 * Encode one RTM_DELNHGFIB message. The id is the whole payload — the object
 * itself is already gone by the time its DEL rides out (see fpm_nhg_unref()),
 * which is why this takes a plain id.
 *
 * \returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
static ssize_t netlink_nhgfib_del_msg_encode(uint32_t dplane_id, void *buf,
					     size_t buflen)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
		char buf[];
	} *req = buf;

	ssize_t ret;

	if (buflen < sizeof(*req))
		return 0;

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req->n.nlmsg_type = RTM_DELNHGFIB;

	req->nhm.nh_family = AF_UNSPEC;

	if (!nl_attr_put32(&req->n, buflen, NHA_ID, dplane_id))
		return 0;

	ret = NLMSG_ALIGN(req->n.nlmsg_len);

	/* Same framing bound as the NEW encode; unreachable for this size. */
	if ((size_t)ret + FPM_HEADER_SIZE > UINT16_MAX) {
		zlog_err("%s: dplane NHG %u message is %zd bytes, too large to frame",
			 __func__, dplane_id, ret);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: RTM_DELNHGFIB, id=%u", __func__, dplane_id);

	return ret;
}

static ssize_t netlink_sidlist_msg_encode(int cmd,
					   struct zebra_dplane_ctx *ctx,
					   uint8_t *data, size_t datalen)
{
	struct rtattr *nest;
	struct zebra_srv6_sidlist *sidlist;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[];
	} *req = (void *)data;

	sidlist = dplane_ctx_get_sidlist(ctx);

	if (datalen < sizeof(*req))
		return 0;

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	req->n.nlmsg_type = cmd;
	req->r.rtm_scope = RT_SCOPE_UNIVERSE;
	req->r.rtm_type = RTN_UNICAST;

	if (!nl_attr_put32(&req->n, datalen, RTA_TABLE, sidlist->segment_count_))
		return false;

	nest = nl_attr_nest(&req->n, datalen, RTA_ENCAP);
	if (!nest)
		return false;

	char sidlist_name[SRV6_SEGMENTLIST_NAME_MAX_LENGTH];
	memset(sidlist_name, 0, sizeof(sidlist_name));
	memcpy(sidlist_name, sidlist->sidlist_name_, sizeof(sidlist_name));
	if (!nl_attr_put(
			&req->n, datalen, FPM_ROUTE_ENCAP_SRV6_ENCAP_SIDLIST_NAME,
			sidlist_name, sizeof(sidlist_name)))
		return false;

	struct zebra_srv6_segment_entry segments[SRV6_SID_INDEX_MAX_NUM];
	memset(segments, 0, sizeof(segments));
	for (uint32_t i = 0; i < sidlist->segment_count_; i++) {
		segments[i].index_ = sidlist->segments_[i].index_;
		segments[i].srv6_sid_value_ = sidlist->segments_[i].srv6_sid_value_;
	}
	if (!nl_attr_put(&req->n, datalen, FPM_ROUTE_ENCAP_SRV6_ENCAP_SIDLIST,
				segments, SRV6_SID_INDEX_MAX_NUM * sizeof(struct zebra_srv6_segment_entry)))
		return false;
	nl_attr_nest_end(&req->n, nest);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t
dplane_fpm_nl_send_br_port_shl_entries(const struct zebra_dplane_ctx *ctx,
				       uint8_t *nl_buf, size_t nl_buf_len)
{
	size_t i;

	/*
	 * The BR port update to FPM uses the private message extensions
	 * defined in kernel_netlink.h
	 */
	struct {
		struct nlmsghdr n;
		struct evpn_shl_msg e;
		char buf[0];
	} *req = (void *)nl_buf;
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	if (nl_buf_len < sizeof(*req))
		return -1;

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct evpn_shl_msg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (DPLANE_OP_BR_PORT_UPDATE == op) {
		req->n.nlmsg_type = RTM_FPM_ADD_EVPN_SHL;
	} else {
		req->n.nlmsg_type = RTM_FPM_DEL_EVPN_SHL;
	}

	req->e.esm_ifindex = dplane_ctx_get_ifindex(ctx);
	req->e.esm_vid = dplane_ctx_get_br_port_vlan_id(ctx);

	if (dplane_ctx_get_br_port_sph_filter_cnt(ctx) > 0) {
		const struct ipaddr *sph_filters =
			dplane_ctx_get_br_port_sph_filters(ctx);
		for (i = 0; i < dplane_ctx_get_br_port_sph_filter_cnt(ctx);
		     i++) {
			if (IS_IPADDR_V4(&sph_filters[i])) {
				if (!nl_attr_put(&req->n, nl_buf_len,
						 FPM_SHL_IPV4_ADDR,
						 &sph_filters[i].ipaddr_v4,
						 sizeof(sph_filters[i].ipaddr_v4)))
					return 0;
			} else if (IS_IPADDR_V6(&sph_filters[i])) {
				if (!nl_attr_put(&req->n, nl_buf_len,
						 FPM_SHL_IPV6_ADDR,
						 &sph_filters[i].ipaddr_v6,
						 sizeof(sph_filters[i].ipaddr_v6)))
					return 0;
			} else {
				/* Unknown address family in SPH filter; skip. */
				continue;
			}
		}
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t
dplane_fpm_nl_send_br_port_df_entries(const struct zebra_dplane_ctx *ctx,
				      uint8_t *nl_buf, size_t nl_buf_len)
{
	struct {
		struct nlmsghdr n;
		struct evpn_df_msg e;
		char buf[0];
	} *req = (void *)nl_buf;
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	if (nl_buf_len < sizeof(*req))
		return -1;

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct evpn_df_msg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	req->e.edm_ifindex = dplane_ctx_get_ifindex(ctx);
	req->e.edm_vid = dplane_ctx_get_br_port_vlan_id(ctx);

	if (DPLANE_OP_BR_PORT_UPDATE == op) {
		const uint32_t flags = dplane_ctx_get_br_port_flags(ctx);

		req->n.nlmsg_type = RTM_FPM_ADD_EVPN_DF;
		req->e.edm_non_df = ((flags & DPLANE_BR_PORT_NON_DF) != 0);
	} else {
		req->n.nlmsg_type = RTM_FPM_DEL_EVPN_DF;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t
dplane_fpm_nl_send_br_port_backup_nhg(const struct zebra_dplane_ctx *ctx,
				      uint8_t *nl_buf, size_t nl_buf_len)
{
	struct {
		struct nlmsghdr n;
		struct evpn_backup_nhg_msg e;
		char buf[0];
	} *req = (void *)nl_buf;

	if (nl_buf_len < sizeof(*req))
		return -1;

	/*
	 * There is currently only a backup NHG per-port, so
	 * only send it on VLAN 0, which represents the entire port.
	 */
	if (dplane_ctx_get_br_port_vlan_id(ctx) != 0)
		return 0;

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct evpn_backup_nhg_msg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	req->e.ebnm_ifindex = dplane_ctx_get_ifindex(ctx);
	req->e.ebnm_backup_nhg_id = dplane_ctx_get_br_port_backup_nhg_id(ctx);

	if (req->e.ebnm_backup_nhg_id > 0) {
		req->n.nlmsg_type = RTM_FPM_ADD_EVPN_ES_BACKUP_NHG;
	} else {
		req->n.nlmsg_type = RTM_FPM_DEL_EVPN_ES_BACKUP_NHG;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t
dplane_fpm_nl_handle_br_port_update(const struct zebra_dplane_ctx *ctx,
				    uint8_t *nl_buf, size_t nl_buf_len)
{
	ssize_t buf_used = 0;
	ssize_t rv = 0;

	/*
	 * DPLANE_OP_BR_PORT_UPDATE/DELETE is used in the context of
	 * EVPN updates. Encode SHL, DF, and backup NHG messages.
	 * SHL and DF always emit at least an nlmsghdr, so a 0/negative
	 * return signals a hard buffer-too-small failure: abort the
	 * BR_PORT encode rather than enqueue a partial update.
	 */
	rv = dplane_fpm_nl_send_br_port_shl_entries(ctx, nl_buf, nl_buf_len);
	if (rv <= 0)
		return rv;
	buf_used += rv;
	nl_buf += rv;
	nl_buf_len -= rv;

	rv = dplane_fpm_nl_send_br_port_df_entries(ctx, nl_buf, nl_buf_len);
	if (rv <= 0)
		return rv;
	buf_used += rv;
	nl_buf += rv;
	nl_buf_len -= rv;

	/*
	 * Backup NHG is per-port and only emitted on VLAN 0; a 0 return
	 * for VLAN != 0 is intentional. Only treat a negative return as
	 * a hard failure here.
	 */
	rv = dplane_fpm_nl_send_br_port_backup_nhg(ctx, nl_buf, nl_buf_len);
	if (rv < 0)
		return rv;
	buf_used += rv;

	return buf_used;
}

#define DPLANE_FPM_NL_BUF_SIZE 65536

/*
 * Free space fpm_process_queue() insists on before it dequeues a context.
 *
 * A legacy context writes exactly one FPM frame, and the wire format caps a
 * frame at UINT16_MAX (65535) bytes, so one DPLANE_FPM_NL_BUF_SIZE of room was
 * a proof that a context which cleared this gate could not then fail its own
 * room check. An nhg-fib context writes a batch -- carried-over DELs, this
 * context's NEWs, then the route message -- so that proof no longer holds at
 * one frame's worth of room.
 *
 * This restores it in practice rather than by construction: with
 * FPM_NHG_PENDING_DELS_MAX bounding the DEL term (~135KiB) and the route frame
 * bounded at 64KiB, only a context building several hundred near-maximal NHGFIB
 * frames of its own can still exceed this window, and that context is caught by
 * the stash-and-retry path instead of being lost. 1MiB of the 8MiB obuf, so the
 * gate costs no meaningful throughput.
 */
#define DPLANE_FPM_NL_MIN_WRITEABLE (DPLANE_FPM_NL_BUF_SIZE * 16)

/*
 * Upper bound on carried-over DELNHGFIB ids before they are flushed as a batch
 * of their own, instead of waiting for the next context (or end of drain) to
 * carry them.
 *
 * pending_dels is the only term of a batch that grows across an entire drain
 * pass -- a churn burst freeing tens of thousands of NHGs would otherwise let a
 * later batch's head alone dwarf the admission window. Bounding it is what
 * makes the retry in fpm_process_queue() provably terminate: every term of
 * batch.total_len then has a ceiling.
 *
 * A DEL frame costs well under 132 bytes on the wire, so this is ~135KiB.
 */
#define FPM_NHG_PENDING_DELS_MAX 1024

/**
 * Whether `bytes` could ever fit in the output buffer, empty or not.
 *
 * Separates "full right now, worth retrying" from "will not fit however long we
 * wait". A batch bigger than the buffer itself is a permanent failure: retrying
 * it forever would park it at the head of the queue and starve every context
 * behind it until the wedge timer forced a reconnect, whose resync would only
 * rebuild the same oversized batch.
 */
static bool fpm_obuf_can_ever_fit(struct fpm_nl_ctx *fnc, size_t bytes)
{
	return bytes <= STREAM_SIZE(fnc->obuf);
}

/**
 * Check that `bytes` more bytes (FPM headers included) still fit in the
 * output buffer, accounting the buffer-full event when they do not.
 *
 * Requires `fnc->obuf_mutex` to be held. `caller` keeps the debug message
 * attributed to the calling function.
 */
static bool fpm_obuf_have_bytes_locked(struct fpm_nl_ctx *fnc, size_t bytes,
				       const char *caller)
{
	if (STREAM_WRITEABLE(fnc->obuf) >= bytes)
		return true;

	atomic_fetch_add_explicit(&fnc->counters.buffer_full, 1,
				  memory_order_relaxed);

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: buffer full: wants to write %zu but has %zu",
			   caller, bytes, STREAM_WRITEABLE(fnc->obuf));

	return false;
}

/**
 * Check that one FPM frame of `nl_buf_len` netlink bytes still fits in the
 * output buffer, accounting the buffer-full event when it does not.
 *
 * Requires `fnc->obuf_mutex` to be held. `caller` keeps the debug message
 * attributed to the calling function.
 */
static bool fpm_obuf_have_room_locked(struct fpm_nl_ctx *fnc,
				      size_t nl_buf_len, const char *caller)
{
	return fpm_obuf_have_bytes_locked(fnc, nl_buf_len + FPM_HEADER_SIZE,
					  caller);
}

/**
 * Write one already encoded netlink buffer into the output stream as a
 * single FPM frame and wake the writer.
 *
 * Requires `fnc->obuf_mutex` to be held.
 *
 * @return 0 on success, -1 when the output buffer is full (nothing written).
 */
static int fpm_obuf_write_locked(struct fpm_nl_ctx *fnc, const uint8_t *nl_buf,
				 size_t nl_buf_len, const char *caller)
{
	uint64_t obytes, obytes_peak;

	/* Check if we have enough buffer space. */
	if (!fpm_obuf_have_room_locked(fnc, nl_buf_len, caller))
		return -1;

	/*
	 * Fill in the FPM header information.
	 *
	 * See FPM_HEADER_SIZE definition for more information.
	 */
	stream_putc(fnc->obuf, 1);
	stream_putc(fnc->obuf, 1);
	stream_putw(fnc->obuf, nl_buf_len + FPM_HEADER_SIZE);

	/* Write current data. */
	stream_write(fnc->obuf, nl_buf, (size_t)nl_buf_len);

	/* Account number of bytes waiting to be written. */
	atomic_fetch_add_explicit(&fnc->counters.obuf_bytes,
				  nl_buf_len + FPM_HEADER_SIZE,
				  memory_order_relaxed);
	obytes = atomic_load_explicit(&fnc->counters.obuf_bytes,
				      memory_order_relaxed);
	obytes_peak = atomic_load_explicit(&fnc->counters.obuf_peak,
					   memory_order_relaxed);
	if (obytes_peak < obytes)
		atomic_store_explicit(&fnc->counters.obuf_peak, obytes,
				      memory_order_relaxed);

	/* Tell the thread to start writing. */
	event_add_write(fnc->fthread->master, fpm_write, fnc, fnc->socket,
			 &fnc->t_write);

	return 0;
}

DEFINE_MTYPE_STATIC(ZEBRA, FPM_FRAME, "FPM pending output frame");

/* One FPM frame pending write: fully encoded netlink message bytes. */
struct fpm_frame {
	uint8_t *buf;
	size_t len;
};

/*
 * Every frame one dplane context produces, in wire order. The batch is the
 * unit of atomicity: its total byte count is known exactly before anything is
 * written, so it is admitted by a single room check and then written to obuf
 * in one critical section — the peer never observes a partially emitted
 * context.
 *
 * count/cap are uint32 so an unusually large batch degrades into a room
 * failure (which the caller can roll back and retry) instead of tripping an
 * assert. The per-frame framing bound is enforced in fpm_frame_batch_add().
 */
struct fpm_frame_batch {
	struct fpm_frame *frames;
	uint32_t count, cap;
	size_t total_len;   /* sum of len + FPM_HEADER_SIZE per frame */
	/*
	 * How many of those frames are NHGFIB messages. The nhgfib_sent
	 * counter is bumped only once the batch reaches obuf, so it counts
	 * frames actually written instead of frames assembled — an assembled
	 * batch can still be rolled back.
	 */
	uint32_t nhgfib_count;
};

/**
 * Append one fully encoded netlink message to the batch. The bytes are
 * copied, so callers may encode every frame into the same scratch buffer.
 *
 * The assert is the per-frame wire bound: the FPM header carries the frame
 * length as a u16 (stream_putw()), so no single frame may exceed UINT16_MAX
 * bytes including that header. Every producer is bounded by it — netlink
 * messages are encoded into a DPLANE_FPM_NL_BUF_SIZE (64KiB) scratch buffer,
 * and P9's NHGFIB encoder must respect the same limit.
 */
static void fpm_frame_batch_add(struct fpm_frame_batch *batch,
				const uint8_t *buf, size_t len)
{
	assert(len > 0 && (len + FPM_HEADER_SIZE) <= UINT16_MAX);

	if (batch->count == batch->cap) {
		batch->cap = batch->cap ? batch->cap * 2 : 16;
		batch->frames = XREALLOC(MTYPE_FPM_FRAME, batch->frames,
					 (size_t)batch->cap *
						 sizeof(*batch->frames));
	}

	batch->frames[batch->count].buf = XCALLOC(MTYPE_FPM_FRAME, len);
	memcpy(batch->frames[batch->count].buf, buf, len);
	batch->frames[batch->count].len = len;
	batch->count++;
	batch->total_len += len + FPM_HEADER_SIZE;
}

static void fpm_frame_batch_free(struct fpm_frame_batch *batch)
{
	uint32_t i;

	for (i = 0; i < batch->count; i++)
		XFREE(MTYPE_FPM_FRAME, batch->frames[i].buf);
	XFREE(MTYPE_FPM_FRAME, batch->frames);
	batch->count = 0;
	batch->cap = 0;
	batch->total_len = 0;
	batch->nhgfib_count = 0;
}

/**
 * Write a whole batch into the output stream as one atomic unit and wake
 * the writer once.
 *
 * Requires `fnc->obuf_mutex` to be held.
 *
 * Callers assemble the complete batch first, so `batch->total_len` is the
 * exact byte count of the write; they admit it with one
 * fpm_obuf_have_bytes_locked(total_len) check under the very same held
 * obuf_mutex and only then call this. Nothing else appends to obuf without
 * that mutex, so both room checks below can no longer fail — they are kept as
 * the last line of defence: if a caller ever admitted a batch it had not
 * fully assembled, the peer must not see a truncated context, so this logs
 * and forces a reconnect (dropping all dplane NHG state and making the peer
 * resync from scratch) instead of writing part of it.
 *
 * @return 0 when every frame was written, -1 when the batch did not fit
 *         and a resync was requested.
 */
static int fpm_frame_batch_write_locked(struct fpm_nl_ctx *fnc,
					struct fpm_frame_batch *batch,
					const char *caller)
{
	uint64_t obytes, obytes_peak;
	uint32_t i;

	if (batch->count == 0)
		return 0;

	if (!fpm_obuf_have_bytes_locked(fnc, batch->total_len, caller)) {
		zlog_err("%s: output buffer cannot take a %u frame batch (%zu bytes), forcing FPM resync",
			 caller, batch->count, batch->total_len);
		FPM_RECONNECT(fnc);
		return -1;
	}

	for (i = 0; i < batch->count; i++) {
		size_t len = batch->frames[i].len;

		/*
		 * Unreachable after the batch check above; kept so an
		 * under-estimating reservation can never truncate a context
		 * on the wire — resync instead.
		 */
		if (!fpm_obuf_have_bytes_locked(fnc, len + FPM_HEADER_SIZE,
						caller)) {
			zlog_err("%s: output buffer exhausted mid-batch at frame %u/%u, forcing FPM resync",
				 caller, i, batch->count);
			FPM_RECONNECT(fnc);
			return -1;
		}

		/*
		 * Fill in the FPM header information.
		 *
		 * See FPM_HEADER_SIZE definition for more information.
		 */
		stream_putc(fnc->obuf, 1);
		stream_putc(fnc->obuf, 1);
		stream_putw(fnc->obuf, len + FPM_HEADER_SIZE);

		/* Write current data. */
		stream_write(fnc->obuf, batch->frames[i].buf, len);

		/* Account number of bytes waiting to be written. */
		atomic_fetch_add_explicit(&fnc->counters.obuf_bytes,
					  len + FPM_HEADER_SIZE,
					  memory_order_relaxed);
		obytes = atomic_load_explicit(&fnc->counters.obuf_bytes,
					      memory_order_relaxed);
		obytes_peak = atomic_load_explicit(&fnc->counters.obuf_peak,
						   memory_order_relaxed);
		if (obytes_peak < obytes)
			atomic_store_explicit(&fnc->counters.obuf_peak, obytes,
					      memory_order_relaxed);
	}

	/* Tell the thread to start writing (once for the whole batch). */
	event_add_write(fnc->fthread->master, fpm_write, fnc, fnc->socket,
			 &fnc->t_write);

	/*
	 * The batch is on the wire now: account its NHGFIB frames. Counting
	 * here rather than at assembly time keeps the counter honest for
	 * batches that end up rolled back or refused for lack of room.
	 */
	fnc->nhg_tables.nhgfib_sent += batch->nhgfib_count;

	return 0;
}

/*
 * NHGFIB message emitters.
 *
 * Both are called with `fnc->obuf_mutex` held and in the design's flush
 * order: the DELs carried over from earlier contexts first, then every NEW of
 * this context (children before parents), then its route message. The DELs
 * this context produces are carried over in turn (see fnc->pending_dels).
 *
 * Emitters only APPEND to the caller's frame batch, they never touch obuf:
 * the batch is written in one piece afterwards, which is what makes the
 * whole context atomic on the wire — and what makes its size exactly known
 * before any byte is written.
 *
 * Each emitter encodes into its own scratch buffer: the caller's buffer
 * already holds the route message of this context, which must survive until
 * the batch is assembled. fpm_frame_batch_add() copies the bytes, so one
 * buffer per call is enough. The encoders refuse anything the FPM framing
 * cannot carry (len + FPM_HEADER_SIZE > UINT16_MAX), which is what keeps the
 * assert in fpm_frame_batch_add() unreachable.
 *
 * @return false on encode failure; the caller then emits nothing at all and
 *         reports the failure to zebra, exactly like a route encode failure.
 */
static bool fpm_emit_nhgfib_new(const struct fpm_dplane_nhg *obj,
				struct fpm_frame_batch *batch)
{
	uint8_t buf[DPLANE_FPM_NL_BUF_SIZE];
	ssize_t rv;

	rv = netlink_nhgfib_obj_msg_encode(obj, buf, sizeof(buf));
	if (rv <= 0) {
		zlog_err("%s: NEWNHGFIB encode failed for dplane NHG %u",
			 __func__, obj->dplane_id);
		return false;
	}

	fpm_frame_batch_add(batch, buf, (size_t)rv);
	batch->nhgfib_count++;

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: NEWNHGFIB id %u level %u flags 0x%x children %u refcount %u",
			   __func__, obj->dplane_id, obj->level, obj->nhg_flags,
			   obj->num_children, obj->refcount);

	return true;
}

static bool fpm_emit_nhgfib_del(uint32_t dplane_id,
				struct fpm_frame_batch *batch)
{
	/* A DEL carries nothing but the id: a small buffer covers it. */
	uint8_t buf[128];
	ssize_t rv;

	rv = netlink_nhgfib_del_msg_encode(dplane_id, buf, sizeof(buf));
	if (rv <= 0) {
		zlog_err("%s: DELNHGFIB encode failed for dplane NHG %u",
			 __func__, dplane_id);
		return false;
	}

	fpm_frame_batch_add(batch, buf, (size_t)rv);
	batch->nhgfib_count++;

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: DELNHGFIB id %u", __func__, dplane_id);

	return true;
}

/*
 * route_nhg_map key: (table_id, afi, prefix, source prefix). The source
 * prefix is only set for srcdest routes and stays all-zero otherwise.
 */
static void fpm_nhg_route_key_from_ctx(const struct zebra_dplane_ctx *ctx,
				       struct fpm_nhg_route_key *key)
{
	const struct prefix *p = dplane_ctx_get_dest(ctx);
	const struct prefix *src = dplane_ctx_get_src(ctx);

	memset(key, 0, sizeof(*key));
	key->table_id = dplane_ctx_get_table(ctx);
	key->afi = (p->family == AF_INET6) ? AFI_IP6 : AFI_IP;
	prefix_copy(&key->p, p);
	/* No source prefix: the memset above leaves family AF_UNSPEC. */
	if (src)
		prefix_copy(&key->src_p, src);
}

/**
 * Append every DEL carried over from earlier contexts to `batch`, in queue
 * order (parent before child, oldest context first).
 *
 * Ordering argument: these ids belong to contexts whose route messages were
 * already written to obuf in earlier batches, so the route message that
 * dereferenced each of them precedes this batch entirely. Emitting them at
 * the HEAD of this batch therefore keeps the design's only ordering
 * requirement — "a DEL arrives after the route message that dereferenced it"
 * — and additionally puts them ahead of every RTM_NEWNHGFIB in this batch,
 * which is what makes id recycling safe (see fpm_nhg.c, "id_free() vs DEL
 * flush").
 *
 * Requires `fnc->obuf_mutex` to be held.
 *
 * @return false when a DEL failed to encode; the caller then emits nothing
 *         and leaves the whole queue in place for the next attempt.
 */
static bool fpm_nhg_pending_dels_add(struct fpm_nl_ctx *fnc,
				     struct fpm_frame_batch *batch)
{
	uint32_t i;

	for (i = 0; i < fnc->pending_dels.count; i++)
		if (!fpm_emit_nhgfib_del(fnc->pending_dels.ids[i].dplane_id,
					 batch))
			return false;

	return true;
}

/**
 * Emit the carried-over DELs as a batch of their own. Bounds how long a
 * deferred DEL can lag behind the route message that dropped its last
 * reference when no further nhg-fib context comes along.
 *
 * Same exact-reservation rule as everywhere else: the batch is assembled
 * first, admitted by a single room check, and the queue is only emptied once
 * the bytes are on the wire. With no room the DELs simply stay queued for the
 * next attempt — a lagging DEL is harmless, it only leaves the peer holding
 * an unreferenced NHG for a while longer. An encode failure is handled the
 * same way, for the same reason.
 *
 * Requires `fnc->obuf_mutex` to be held.
 */
static void fpm_nhg_pending_dels_flush_locked(struct fpm_nl_ctx *fnc,
					      const char *caller)
{
	struct fpm_frame_batch batch = {};

	if (fnc->pending_dels.count == 0)
		return;

	if (!fpm_nhg_pending_dels_add(fnc, &batch)) {
		fpm_frame_batch_free(&batch);
		return;
	}

	if (!fpm_obuf_have_bytes_locked(fnc, batch.total_len, caller)) {
		fpm_frame_batch_free(&batch);
		return;
	}

	if (fpm_frame_batch_write_locked(fnc, &batch, caller) == 0)
		fpm_nhg_del_queue_reset(&fnc->pending_dels);

	fpm_frame_batch_free(&batch);
}

/*
 * Debug probe for the resolving-prefix backwalk: the dplane-side replay of
 * zebra's NHT.
 *
 * A route event whose prefix is a resolving prefix in the index is the signal
 * that will eventually make fpmsyncd backwalk — on DELETE the resolution is
 * gone and the peer has to converge away from it, on INSTALL/UPDATE it has to
 * repair the resolution against the new route. The objects to act on are
 * exactly the bucket's contents; for now they are only logged, so the wire
 * signal can be designed against observed behaviour.
 *
 * Only an exact prefix match is reported. A more specific route taking over as
 * the resolver is a separate case that zebra re-resolves itself, and it is
 * deliberately outside this probe.
 *
 * Requires `fnc->obuf_mutex`, which is what serializes the tables.
 */
static void fpm_nhg_rv_probe_route(struct fpm_nl_ctx *fnc,
				   const struct zebra_dplane_ctx *ctx,
				   enum dplane_op_e op)
{
	const struct fpm_nhg_resolved_bucket *b;
	const struct prefix *p = dplane_ctx_get_dest(ctx);
	vrf_id_t vrf_id = dplane_ctx_get_vrf(ctx);
	char nhbuf[NEXTHOP_STRLEN];
	uint32_t i;

	/*
	 * The index is keyed by the VRF the nexthop resolved in, which is the
	 * VRF the resolving route lives in — so it is this event's VRF even
	 * when the route owning the NHG sits in another one (VRF leak).
	 */
	b = fpm_nhg_resolved_lookup(&fnc->nhg_tables, vrf_id, p);
	if (b == NULL)
		return;

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("nhg-fib backwalk: %s %pFX vrf %u is a resolving prefix for %u dplane NHG(s), trigger not wired yet",
			   dplane_op2str(op), p, vrf_id, b->count);

	for (i = 0; i < b->count; i++) {
		const struct fpm_dplane_nhg *obj = b->objs[i];

		if (IS_ZEBRA_DEBUG_FPM) {
			if (obj->nh)
				nexthop2str(obj->nh, nhbuf, sizeof(nhbuf));
			else
				strlcpy(nhbuf, "(none)", sizeof(nhbuf));

			zlog_debug("nhg-fib backwalk:   dplane NHG %u (rib nhg %u), nexthop %s",
				   obj->dplane_id, obj->resolved_via, nhbuf);
		}
	}
}

/**
 * Route operation handling in nhg-fib mode (design §4.2.1 "Per-op
 * handling"): the route event itself drives the dplane NHG object
 * lifecycle and the route message carries a plugin allocated RTA_NH_ID (or,
 * for SRv6 VPN routes, the two SRv6 encap id attributes — design §3.2).
 *
 * The whole sequence runs under `obuf_mutex`, which also serializes the
 * NHG tables against the other thread enqueueing route ops, and keeps the
 * emitted order atomic in the byte stream.
 *
 * Every write is EXACTLY reserved, in this order:
 *
 *  1. build the object tree (pure state, rollback-able) and encode the
 *     route frame into the caller's scratch buffer;
 *  2. assemble the whole batch: first the DELs carried over from earlier
 *     contexts, then this context's NEWs (children before parents), then its
 *     route frame. Nothing is written yet, so the context is still fully
 *     undoable — an NHGFIB encode failure here is handled just like a route
 *     encode failure (rollback, nothing emitted, REQUEST_FAILURE);
 *  3. admit the batch with ONE room check for its exact total length. On
 *     failure the build is rolled back, the map keeps pointing at the old
 *     object, the carried-over DELs stay queued and -1 is returned so the
 *     caller can retry (or report the failure to zebra);
 *  4. write the batch in one piece and drop the carried-over DELs: they are
 *     on the wire now;
 *  5. only then mutate state (map upsert, ref of the new top, unref of the
 *     old one). The unref is what produces DEL ids, and it frees the objects
 *     as it goes — there is no undo past this point, which is exactly why it
 *     comes last: the write no longer depends on any of its results. The ids
 *     it produces are appended to fnc->pending_dels and ride out at the head
 *     of the next batch (or in the end-of-drain flush), which is where the
 *     need for any guessed DEL allowance disappears.
 *
 * @param nl_buf      caller owned scratch buffer for the route frame.
 * @param nl_buf_size size of that buffer.
 * @return 0 on success or on a handled failure (nothing emitted, state
 *         unchanged), -1 when the output buffer is full.
 */
static int fpm_nl_enqueue_route_nhg_fib(struct fpm_nl_ctx *fnc,
					struct zebra_dplane_ctx *ctx,
					enum dplane_op_e op, uint8_t *nl_buf,
					size_t nl_buf_size)
{
	struct fpm_nhg_staging newq = {};
	struct fpm_frame_batch batch = {};
	struct fpm_dplane_nhg *new_top = NULL, *old_top;
	struct fpm_nhg_route_key key;
	size_t nl_buf_len = 0, route_off;
	bool encode_ok = true;
	struct nlmsghdr *n;
	ssize_t rv;
	uint32_t i;
	int ret;
	/*
	 * SRv6 VPN routes keep their own message pair
	 * (RTM_NEW/DELSRV6VPNROUTE), which carries the NHG ids as two encap
	 * attributes instead of RTA_NH_ID (design §3.2). Everything else about
	 * this path — derivation, ordering, atomicity — is identical.
	 */
	bool srv6_vpn = has_srv6_sidlist_nexthop(ctx);

	fpm_nhg_route_key_from_ctx(ctx, &key);

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	/*
	 * Explicit removal: DELETE, and UPDATE when route replace semantics
	 * are disabled (same message pair the legacy path emits).
	 */
	if (op == DPLANE_OP_ROUTE_DELETE || op == DPLANE_OP_ROUTE_UPDATE) {
		if (srv6_vpn) {
			/*
			 * The peer removes the route by prefix and ignores the
			 * two ids on a delete, but both attributes must be
			 * present for it to accept the message: send the object
			 * this route currently references (0 when the plugin has
			 * never seen it, e.g. after a reconnect flush).
			 */
			old_top = fpm_nhg_route_get(&fnc->nhg_tables, &key);
			rv = netlink_vpn_route_msg_encode(RTM_DELROUTE, ctx, nl_buf,
							  nl_buf_size,
							  old_top ? old_top->dplane_id : 0,
							  old_top ? old_top->dplane_id : 0);
		} else {
			rv = netlink_route_multipath_msg_encode(RTM_DELROUTE, ctx,
							       nl_buf, nl_buf_size,
							       true, false, false);
		}
		if (rv <= 0) {
			zlog_err("%s: route delete encode failed", __func__);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		nl_buf_len = (size_t)rv;
	}

	if (op != DPLANE_OP_ROUTE_DELETE) {
		new_top = fpm_nhg_build(&fnc->nhg_tables,
					dplane_ctx_get_ng(ctx)->nexthop, &newq);
		if (new_top == NULL) {
			zlog_err("%s: fpm_nhg_build failed", __func__);
			fpm_nhg_rollback(&fnc->nhg_tables, &newq);
			fpm_nhg_staging_free(&newq);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		route_off = nl_buf_len;
		if (srv6_vpn) {
			/*
			 * Received id = the L-A object; nh id = its resolved
			 * view, which the peer derives from that very same NHGFIB
			 * message, so both attributes carry the same dplane id
			 * (design §3.2).
			 */
			rv = netlink_vpn_route_msg_encode(RTM_NEWROUTE, ctx,
							  &nl_buf[route_off],
							  nl_buf_size - route_off,
							  new_top->dplane_id,
							  new_top->dplane_id);
			if (rv > 0)
				nl_buf_len = route_off + (size_t)rv;
		} else {
			/*
			 * force_nhg is false on purpose: it would make the
			 * encoder emit RTA_NH_ID from dplane_ctx_get_nhe_id(),
			 * which is the zebra NHG id. The wire id must be the
			 * plugin allocated dplane id, so the attribute is
			 * appended below instead.
			 */
			rv = netlink_route_multipath_msg_encode(RTM_NEWROUTE, ctx,
							       &nl_buf[route_off],
							       nl_buf_size - route_off,
							       true, false,
							       fnc->use_route_replace);
			if (rv > 0) {
				/*
				 * Append RTA_NH_ID to the message just encoded.
				 * The encoder builds the message through the very
				 * same nl_attr_put*() helpers and returns
				 * NLMSG_ALIGN(nlmsg_len), so the assembled header
				 * is complete and every nested attribute is
				 * already closed: one more top level attribute is
				 * exactly what the encoder itself does for
				 * RTA_PREFSRC. nl_attr_put32() appends at
				 * NLMSG_ALIGN(nlmsg_len) and bounds itself by
				 * maxlen measured from the start of the header,
				 * hence nl_buf_size - route_off. Alignment of the
				 * cast is inherited from the encoder, which casts
				 * the same address to its own header struct
				 * (route_off is NLMSG_ALIGN'ed).
				 */
				n = (struct nlmsghdr *)&nl_buf[route_off];
				if (!nl_attr_put32(n, nl_buf_size - route_off,
						   RTA_NH_ID, new_top->dplane_id))
					rv = 0;
				else
					nl_buf_len = route_off +
						     NLMSG_ALIGN(n->nlmsg_len);
			}
		}
		if (rv <= 0) {
			/* Encode failure: roll back and emit nothing at all. */
			zlog_err("%s: route encode failed, dropping ctx",
				 __func__);
			fpm_nhg_rollback(&fnc->nhg_tables, &newq);
			fpm_nhg_staging_free(&newq);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}
	}

	/* We must know if someday a message goes beyond 65KiB. */
	assert((nl_buf_len + FPM_HEADER_SIZE) <= UINT16_MAX);

	/*
	 * Assemble the complete batch while the context is still fully undoable.
	 * Wire order: carried-over DELs -> this context's NEWs (children first)
	 * -> route message.
	 *
	 * The NEWs are encoded before the mutation below, which is safe because
	 * the mutation changes nothing an NHGFIB message carries: it only moves
	 * refcounts and the route map entry, and it only frees objects that
	 * existed before this build (a newly built object cannot be a child of
	 * the old top, so the unref cascade can never reach one).
	 */
	if (!fpm_nhg_pending_dels_add(fnc, &batch))
		encode_ok = false;

	for (i = 0; encode_ok && i < newq.count; i++)
		encode_ok = fpm_emit_nhgfib_new(newq.objs[i], &batch);

	/*
	 * An NHGFIB that cannot be encoded is handled exactly like a route that
	 * cannot be encoded: nothing of this context goes out, the build is
	 * rolled back, the carried-over DELs stay queued and zebra is told the
	 * route was not programmed. Emitting the route alone would leave it
	 * pointing at an id the peer never learned.
	 */
	if (!encode_ok) {
		zlog_err("%s: NHGFIB encode failed, dropping ctx", __func__);
		fpm_nhg_rollback(&fnc->nhg_tables, &newq);
		fpm_nhg_staging_free(&newq);
		fpm_frame_batch_free(&batch);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
		return 0;
	}

	if (nl_buf_len)
		fpm_frame_batch_add(&batch, nl_buf, nl_buf_len);

	/*
	 * batch.total_len is now the EXACT byte count of the write, so this
	 * single check is the whole reservation — no upper bound heuristic is
	 * involved anymore. On failure nothing is emitted, no state moves, the
	 * map keeps pointing at the old object and the carried-over DELs stay
	 * queued, so the caller can retry the whole context.
	 */
	if (!fpm_obuf_have_bytes_locked(fnc, batch.total_len, __func__)) {
		size_t batch_len = batch.total_len;
		bool never = !fpm_obuf_can_ever_fit(fnc, batch_len);

		fpm_nhg_rollback(&fnc->nhg_tables, &newq);
		fpm_nhg_staging_free(&newq);
		fpm_frame_batch_free(&batch);

		/*
		 * Bigger than the buffer will ever be: waiting cannot help, and
		 * asking the caller to retry would block every context behind
		 * this one. Report it like an encode failure instead — one loud
		 * error, and zebra learns the route is not programmed.
		 */
		if (never) {
			zlog_err("%s: batch of %zu bytes exceeds the %zu byte output buffer, dropping ctx (%pFX table %u)",
				 __func__, batch_len, STREAM_SIZE(fnc->obuf),
				 dplane_ctx_get_dest(ctx),
				 dplane_ctx_get_table(ctx));
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		return -1;
	}

	/* One atomic write for the whole context. */
	ret = fpm_frame_batch_write_locked(fnc, &batch, __func__);
	fpm_frame_batch_free(&batch);
	fpm_nhg_staging_free(&newq);

	/*
	 * The carried-over DELs are on the wire (or a resync was forced, which
	 * invalidates every id anyway): stop carrying them.
	 */
	fpm_nhg_del_queue_reset(&fnc->pending_dels);

	/* Past this point the state change is committed and not undoable. */
	if (op == DPLANE_OP_ROUTE_DELETE) {
		old_top = fpm_nhg_route_pop(&fnc->nhg_tables, &key);
	} else {
		old_top = fpm_nhg_route_get(&fnc->nhg_tables, &key);
		fpm_nhg_route_set(&fnc->nhg_tables, &key, new_top,
				  dplane_ctx_get_nhe_id(ctx));
		fpm_nhg_ref(new_top);
	}
	/*
	 * ref-then-unref also covers the "same tree re-sent" case: there
	 * old_top == new_top, the two operations net to zero and no DEL is
	 * staged.
	 *
	 * The DELs land in fnc->pending_dels: the route message that
	 * dereferenced them has just been written, so emitting them at the head
	 * of the next batch keeps them strictly after it.
	 */
	if (old_top)
		fpm_nhg_unref(&fnc->nhg_tables, old_top, &fnc->pending_dels);

	/*
	 * Keep the deferred DEL list bounded. Left alone it grows for as long as
	 * the drain pass runs, and its frames are emitted at the HEAD of the
	 * next batch — so a churn burst freeing tens of thousands of NHGs would
	 * make a later, unrelated context's batch huge for reasons that have
	 * nothing to do with that context. Flushing here is legal for the same
	 * reason the end-of-drain flush is: this context's route message is
	 * already on the wire, so these DELs still arrive strictly after it.
	 */
	if (fnc->pending_dels.count >= FPM_NHG_PENDING_DELS_MAX)
		fpm_nhg_pending_dels_flush_locked(fnc, __func__);

	/*
	 * Probed only for a committed context: an event that was rolled back or
	 * retried must not look like a resolution change to the peer.
	 */
	fpm_nhg_rv_probe_route(fnc, ctx, op);

	return ret;
}

/**
 * Drop any nhg-fib state this route still owns, queueing the resulting
 * DELNHGFIB ids for the next batch.
 *
 * Needed when a prefix leaves the nhg-fib path while keeping its identity,
 * i.e. a route becoming an SRv6 local SID route: local SID contexts are the
 * only route contexts still handled by the legacy encoders in nhg-fib mode,
 * so without this the route_nhg_map would keep a stale entry and the
 * reference it holds would never be released — the top object (and everything
 * below it) would leak until the next reconnect flush.
 *
 * State only: no message is emitted here. Emitting the DELs at this point
 * would put them BEFORE the legacy route message this context is about to
 * encode, i.e. before the very message that drops the last reference — the
 * one ordering the design forbids. Handing them to fnc->pending_dels instead
 * makes them ride out with the next nhg-fib batch or with the end-of-drain
 * flush, strictly after this context's route message. The lag is harmless:
 * the peer keeps an unreferenced NHG for a moment longer, and the id cannot
 * be reused ahead of its DEL because every NEW is emitted behind the pending
 * DELs (see fpm_nhg_pending_dels_add()).
 *
 * obuf_mutex is still held: it is what serializes the tables and
 * fnc->pending_dels against the other thread.
 */
static void fpm_nhg_fib_forget_route(struct fpm_nl_ctx *fnc,
				     struct zebra_dplane_ctx *ctx)
{
	struct fpm_dplane_nhg *old_top;
	struct fpm_nhg_route_key key;

	fpm_nhg_route_key_from_ctx(ctx, &key);

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	old_top = fpm_nhg_route_pop(&fnc->nhg_tables, &key);
	if (old_top == NULL)
		return;

	fpm_nhg_unref(&fnc->nhg_tables, old_top, &fnc->pending_dels);
}

/**
 * Encode data plane operation context into netlink and enqueue it in the FPM
 * output buffer.
 *
 * @param fnc the netlink FPM context.
 * @param ctx the data plane operation context data.
 * @return 0 on success or -1 on not enough space.
 */
static int fpm_nl_enqueue(struct fpm_nl_ctx *fnc, struct zebra_dplane_ctx *ctx)
{
	uint8_t nl_buf[DPLANE_FPM_NL_BUF_SIZE];
	size_t nl_buf_len;
	ssize_t rv;
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	struct nexthop *nexthop;

	/*
	 * If we were configured to not use next hop groups, then quit as soon
	 * as possible.
	 */
	if ((!fnc->use_nhg)
	    && (op == DPLANE_OP_NH_DELETE || op == DPLANE_OP_NH_INSTALL
		|| op == DPLANE_OP_NH_UPDATE))
			return 0;
 
	/*
	 * Ignore route from default table, because when mgmt port goes down,
	 * zebra will remove the default route and causing ASIC to blackhole IO.
	 */
	if (dplane_ctx_get_table(ctx) == RT_TABLE_DEFAULT) {
		zlog_debug("%s: discard default table route", __func__);
		return 0;
	}

	nl_buf_len = 0;

	/*
	 * If route replace is enabled then directly encode the install which
	 * is going to use `NLM_F_REPLACE` (instead of delete/add operations).
	 */
	if (fnc->use_route_replace && op == DPLANE_OP_ROUTE_UPDATE) {
		nexthop = dplane_ctx_get_ng(ctx)->nexthop;
		if (nexthop && nexthop->nh_srv6) {
			// Don't change op for srv6 yet. Not sure if update
			// semantics will work or not
		} else {
			op = DPLANE_OP_ROUTE_INSTALL;
		}
	}

	/*
	 * nhg-fib mode: route events drive the dplane NHG object lifecycle and
	 * the route message carries a plugin allocated NHG id (design §4.2.1).
	 * SRv6 VPN routes take the same path — they carry their ids in the two
	 * SRv6 encap attributes instead of RTA_NH_ID (design §3.2).
	 *
	 * SRv6 local SID routes are the one exception: their message
	 * (RTM_NEW/DELSRV6LOCALSID) references no NHG at all, so deriving
	 * objects for them would publish NHGs nothing can ever reference —
	 * real ASIC resources in fpmsyncd. They stay on the legacy encoder.
	 */
	if (fnc->use_nhg_fib &&
	    (op == DPLANE_OP_ROUTE_INSTALL || op == DPLANE_OP_ROUTE_UPDATE ||
	     op == DPLANE_OP_ROUTE_DELETE)) {
		if (!has_srv6_localsid_nexthop(ctx))
			return fpm_nl_enqueue_route_nhg_fib(fnc, ctx, op, nl_buf,
							    sizeof(nl_buf));
		/*
		 * A prefix can transition into a local SID route: release the
		 * nhg-fib state it owned before handing it to the legacy
		 * encoders below.
		 */
		fpm_nhg_fib_forget_route(fnc, ctx);
	}

	switch (op) {
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		if (has_srv6_nexthop(ctx)) {
			rv = netlink_srv6_msg_encode(RTM_DELROUTE, ctx,
								nl_buf, sizeof(nl_buf),
								true, fnc->use_nhg);
			if (rv <= 0) {
				zlog_err(
					"%s: netlink_srv6_msg_encode failed",
					__func__);
				dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
				return 0;
			}
		} else {
			rv = netlink_route_multipath_msg_encode(RTM_DELROUTE, ctx,
								nl_buf, sizeof(nl_buf),
								true, fnc->use_nhg, false);
			if (rv <= 0) {
				zlog_err(
					"%s: netlink_route_multipath_msg_encode failed",
					__func__);
				dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
				return 0;
			}
		}

		nl_buf_len = (size_t)rv;

		/* UPDATE operations need a INSTALL, otherwise just quit. */
		if (op == DPLANE_OP_ROUTE_DELETE)
			break;

		/* FALL THROUGH */
	case DPLANE_OP_ROUTE_INSTALL:
		if (has_srv6_nexthop(ctx)) {
			rv = netlink_srv6_msg_encode(
				RTM_NEWROUTE, ctx, &nl_buf[nl_buf_len],
				sizeof(nl_buf) - nl_buf_len, true, fnc->use_nhg);
			if (rv <= 0) {
				zlog_err(
					"%s: netlink_srv6_msg_encode failed",
					__func__);
				dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
				return 0;
			}
		} else {
			rv = netlink_route_multipath_msg_encode(
				RTM_NEWROUTE, ctx, &nl_buf[nl_buf_len],
				sizeof(nl_buf) - nl_buf_len, true, fnc->use_nhg,
				fnc->use_route_replace);
			if (rv <= 0) {
				zlog_err(
					"%s: netlink_route_multipath_msg_encode failed",
					__func__);
				dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
				return 0;
			}
		}

		nl_buf_len += (size_t)rv;

		break;

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		rv = netlink_macfdb_update_ctx(ctx, nl_buf, sizeof(nl_buf));
		if (rv <= 0) {
			zlog_err("%s: netlink_macfdb_update_ctx failed",
				 __func__);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		break;

	/*
	 * Kernel NHG events. In nhg-fib mode they are ignored: NHGFIB objects
	 * are derived from route events instead, and use_nhg (which gates this
	 * whole group above) is mutually exclusive with use_nhg_fib.
	 */
	case DPLANE_OP_NH_DELETE:
		rv = netlink_nexthop_msg_encode(RTM_DELNEXTHOP, ctx, nl_buf,
						sizeof(nl_buf), true);
		if (rv <= 0) {
			zlog_err("%s: netlink_nexthop_msg_encode failed",
				 __func__);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		break;
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
		rv = netlink_nexthop_msg_encode(RTM_NEWNEXTHOP, ctx, nl_buf,
						sizeof(nl_buf), true);
		if (rv <= 0) {
			zlog_err("%s: netlink_nexthop_msg_encode failed",
				 __func__);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		break;
	case DPLANE_OP_SID_LIST_DELETE:
		rv = netlink_sidlist_msg_encode(
				RTM_DELSIDLIST, ctx, nl_buf, sizeof(nl_buf));
		if (rv <= 0) {
			zlog_err(
				"%s: netlink_srv6_msg_encode failed",
				__func__);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}
		nl_buf_len += (size_t)rv;
		break;
	case DPLANE_OP_SID_LIST_INSTALL:
	case DPLANE_OP_SID_LIST_UPDATE:
		rv = netlink_sidlist_msg_encode(
				RTM_NEWSIDLIST, ctx, nl_buf, sizeof(nl_buf));
		if (rv <= 0) {
			zlog_err(
				"%s: netlink_srv6_msg_encode failed",
				__func__);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}
		nl_buf_len += (size_t)rv;
		break;

	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
		rv = netlink_lsp_msg_encoder(ctx, nl_buf, sizeof(nl_buf));
		if (rv <= 0) {
			zlog_err("%s: netlink_lsp_msg_encoder failed",
				 __func__);
			dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		nl_buf_len += (size_t)rv;
		break;

	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
		if (strmatch(dplane_ctx_get_ifname(ctx), "lo"))
			event_add_timer(fnc->fthread->master, fpm_srv6_route_reset,
				 fnc, 0, &fnc->t_ribreset);
		break;

	case DPLANE_OP_BR_PORT_UPDATE:
	case DPLANE_OP_BR_PORT_DELETE:
		rv = dplane_fpm_nl_handle_br_port_update(ctx, nl_buf,
							  sizeof(nl_buf));
		if (rv <= 0) {
			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug("%s: br_port encode returned %zd",
					   __func__, rv);
			dplane_ctx_set_status(ctx,
					     ZEBRA_DPLANE_REQUEST_FAILURE);
			return 0;
		}

		nl_buf_len += (size_t)rv;
		break;

	/* Un-handled by FPM at this time. */
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
	case DPLANE_OP_GRE_SET:
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_INTF_NETCONFIG:
	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
	case DPLANE_OP_NONE:
	case DPLANE_OP_STARTUP_STAGE:
		break;

	}

	/* Skip empty enqueues. */
	if (nl_buf_len == 0)
		return 0;

	/* We must know if someday a message goes beyond 65KiB. */
	assert((nl_buf_len + FPM_HEADER_SIZE) <= UINT16_MAX);

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	return fpm_obuf_write_locked(fnc, nl_buf, nl_buf_len, __func__);
}

/*
 * LSP walk/send functions
 */
struct fpm_lsp_arg {
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	bool complete;
};

static int fpm_lsp_send_cb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_lsp *lsp = bucket->data;
	struct fpm_lsp_arg *fla = arg;

	/* Skip entries which have already been sent */
	if (CHECK_FLAG(lsp->flags, LSP_FLAG_FPM))
		return HASHWALK_CONTINUE;

	dplane_ctx_reset(fla->ctx);
	dplane_ctx_lsp_init(fla->ctx, DPLANE_OP_LSP_INSTALL, lsp);

	if (fpm_nl_enqueue(fla->fnc, fla->ctx) == -1) {
		fla->complete = false;
		return HASHWALK_ABORT;
	}

	/* Mark entry as sent */
	SET_FLAG(lsp->flags, LSP_FLAG_FPM);
	return HASHWALK_CONTINUE;
}

static void fpm_lsp_send(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct zebra_vrf *zvrf = vrf_info_lookup(VRF_DEFAULT);
	struct fpm_lsp_arg fla;

	fla.fnc = fnc;
	fla.ctx = dplane_ctx_alloc();
	fla.complete = true;

	hash_walk(zvrf->lsp_table, fpm_lsp_send_cb, &fla);

	dplane_ctx_fini(&fla.ctx);

	if (fla.complete) {
		WALK_FINISH(fnc, FNE_LSP_FINISHED);

		/* Now move onto routes */
		event_add_timer(zrouter.master, fpm_nhg_reset, fnc, 0,
				 &fnc->t_nhgreset);
	} else {
		/* Didn't finish - reschedule LSP walk */
		event_add_timer(zrouter.master, fpm_lsp_send, fnc, 0,
				 &fnc->t_lspwalk);
	}
}

/*
 * Next hop walk/send functions.
 */
struct fpm_nhg_arg {
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	bool complete;
};

static int fpm_nhg_send_cb(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = bucket->data;
	struct fpm_nhg_arg *fna = arg;

	/* This entry was already sent, skip it. */
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_FPM))
		return HASHWALK_CONTINUE;

	/* Reset ctx to reuse allocated memory, take a snapshot and send it. */
	dplane_ctx_reset(fna->ctx);
	dplane_ctx_nexthop_init(fna->ctx, DPLANE_OP_NH_INSTALL, nhe);
	if (fpm_nl_enqueue(fna->fnc, fna->ctx) == -1) {
		/* Our buffers are full, lets give it some cycles. */
		fna->complete = false;
		return HASHWALK_ABORT;
	}

	/* Mark group as sent, so it doesn't get sent again. */
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_FPM);

	return HASHWALK_CONTINUE;
}

static void fpm_nhg_send(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct fpm_nhg_arg fna;

	fna.fnc = fnc;
	fna.ctx = dplane_ctx_alloc();
	fna.complete = true;

	/* Send next hops. */
	if (fnc->use_nhg)
		hash_walk(zrouter.nhgs_id, fpm_nhg_send_cb, &fna);

	/* `free()` allocated memory. */
	dplane_ctx_fini(&fna.ctx);

	/* We are done sending next hops, lets install the routes now. */
	if (fna.complete) {
		WALK_FINISH(fnc, FNE_NHG_FINISHED);
		event_add_timer(zrouter.master, fpm_rib_reset, fnc, 0,
				 &fnc->t_ribreset);
	} else /* Otherwise reschedule next hop group again. */
		event_add_timer(zrouter.master, fpm_nhg_send, fnc, 0,
				 &fnc->t_nhgwalk);
}

/**
 * Send all RIB installed routes to the connected data plane.
 */
static void fpm_rib_send(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_table *rt;
	struct zebra_dplane_ctx *ctx;
	rib_tables_iter_t rt_iter;

	/* Allocate temporary context for all transactions. */
	ctx = dplane_ctx_alloc();

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			dest = rib_dest_from_rnode(rn);
			/* Skip bad route entries. */
			if (dest == NULL || dest->selected_fib == NULL)
				continue;

			/* Check for already sent routes. */
			if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM))
				continue;

			/* Enqueue route install. */
			dplane_ctx_reset(ctx);
			dplane_ctx_route_init(ctx, DPLANE_OP_ROUTE_INSTALL, rn,
					      dest->selected_fib);
			if (fpm_nl_enqueue(fnc, ctx) == -1) {
				/* Free the temporary allocated context. */
				dplane_ctx_fini(&ctx);

				event_add_timer(zrouter.master, fpm_rib_send,
						 fnc, 1, &fnc->t_ribwalk);
				return;
			}

			/* Mark as sent. */
			SET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		}
	}

	/* Free the temporary allocated context. */
	dplane_ctx_fini(&ctx);

	/* All RIB routes sent! */
	WALK_FINISH(fnc, FNE_RIB_FINISHED);

	/* Schedule next event: RMAC reset. */
	event_add_event(zrouter.master, fpm_rmac_reset, fnc, 0,
			 &fnc->t_rmacreset);
}

/*
 * The next three functions will handle RMAC enqueue.
 */
struct fpm_rmac_arg {
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	struct zebra_l3vni *zl3vni;
	bool complete;
};

static void fpm_enqueue_rmac_table(struct hash_bucket *bucket, void *arg)
{
	struct fpm_rmac_arg *fra = arg;
	struct zebra_mac *zrmac = bucket->data;
	struct zebra_if *zif = fra->zl3vni->vxlan_if->info;
	const struct zebra_l2info_vxlan *vxl = &zif->l2info.vxl;
	struct zebra_vxlan_vni *vni;
	struct zebra_if *br_zif;
	vlanid_t vid;
	bool sticky;

	/* Entry already sent. */
	if (CHECK_FLAG(zrmac->flags, ZEBRA_MAC_FPM_SENT) || !fra->complete)
		return;

	sticky = !!CHECK_FLAG(zrmac->flags,
			      (ZEBRA_MAC_STICKY | ZEBRA_MAC_REMOTE_DEF_GW));
	br_zif = (struct zebra_if *)(zif->brslave_info.br_if->info);
	vni = zebra_vxlan_if_vni_find(zif, fra->zl3vni->vni);
	vid = IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif) ? vxl->vni_info.vni.access_vlan : 0;

	dplane_ctx_reset(fra->ctx);
	dplane_ctx_set_op(fra->ctx, DPLANE_OP_MAC_INSTALL);
	dplane_mac_init(fra->ctx, fra->zl3vni->vxlan_if,
			zif->brslave_info.br_if, vid,
			&zrmac->macaddr, vni->vni, &zrmac->fwd_info.r_vtep_ip, sticky,
			0 /*nhg*/, 0 /*update_flags*/);
	if (fpm_nl_enqueue(fra->fnc, fra->ctx) == -1) {
		event_add_timer(zrouter.master, fpm_rmac_send,
				 fra->fnc, 1, &fra->fnc->t_rmacwalk);
		fra->complete = false;
	}
}

static void fpm_enqueue_l3vni_table(struct hash_bucket *bucket, void *arg)
{
	struct fpm_rmac_arg *fra = arg;
	struct zebra_l3vni *zl3vni = bucket->data;

	fra->zl3vni = zl3vni;
	hash_iterate(zl3vni->rmac_table, fpm_enqueue_rmac_table, zl3vni);
}

static void fpm_rmac_send(struct event *t)
{
	struct fpm_rmac_arg fra;

	fra.fnc = EVENT_ARG(t);
	fra.ctx = dplane_ctx_alloc();
	fra.complete = true;
	hash_iterate(zrouter.l3vni_table, fpm_enqueue_l3vni_table, &fra);
	dplane_ctx_fini(&fra.ctx);

	/* RMAC walk completed. */
	if (fra.complete)
		WALK_FINISH(fra.fnc, FNE_RMAC_FINISHED);
}

/*
 * Resets the next hop FPM flags so we send all next hops again.
 */
static void fpm_nhg_reset_cb(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = bucket->data;

	/* Unset FPM installation flag so it gets installed again. */
	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_FPM);
}

static void fpm_nhg_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);

	hash_iterate(zrouter.nhgs_id, fpm_nhg_reset_cb, NULL);

	/* Schedule next step: send next hop groups. */
	event_add_event(zrouter.master, fpm_nhg_send, fnc, 0, &fnc->t_nhgwalk);
}

/*
 * Resets the LSP FPM flag so we send all LSPs again.
 */
static void fpm_lsp_reset_cb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_lsp *lsp = bucket->data;

	UNSET_FLAG(lsp->flags, LSP_FLAG_FPM);
}

static void fpm_lsp_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct zebra_vrf *zvrf = vrf_info_lookup(VRF_DEFAULT);

	hash_iterate(zvrf->lsp_table, fpm_lsp_reset_cb, NULL);

	/* Schedule next step: send LSPs */
	event_add_event(zrouter.master, fpm_lsp_send, fnc, 0, &fnc->t_lspwalk);
}

/**
 * Resets the RIB FPM flags so we send all routes again.
 */
static void fpm_rib_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_table *rt;
	rib_tables_iter_t rt_iter;

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			dest = rib_dest_from_rnode(rn);
			/* Skip bad route entries. */
			if (dest == NULL)
				continue;

			UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		}
	}

	/* Schedule next step: send RIB routes. */
	event_add_event(zrouter.master, fpm_rib_send, fnc, 0, &fnc->t_ribwalk);
}

/*
 * The next three function will handle RMAC table reset.
 */
static void fpm_unset_rmac_table(struct hash_bucket *bucket, void *arg)
{
	struct zebra_mac *zrmac = bucket->data;

	UNSET_FLAG(zrmac->flags, ZEBRA_MAC_FPM_SENT);
}

static void fpm_unset_l3vni_table(struct hash_bucket *bucket, void *arg)
{
	struct zebra_l3vni *zl3vni = bucket->data;

	hash_iterate(zl3vni->rmac_table, fpm_unset_rmac_table, zl3vni);
}

static void fpm_rmac_reset(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);

	hash_iterate(zrouter.l3vni_table, fpm_unset_l3vni_table, NULL);

	/* Schedule next event: send RMAC entries. */
	event_add_event(zrouter.master, fpm_rmac_send, fnc, 0,
			 &fnc->t_rmacwalk);
}

static void fpm_process_wedged(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);

	zlog_warn("%s: Connection unable to write to peer for over %u seconds, resetting",
		  __func__, DPLANE_FPM_NL_WEDGIE_TIME);

	atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
				  memory_order_relaxed);
	FPM_RECONNECT(fnc);
}

static void fpm_process_queue(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	struct zebra_dplane_ctx *ctx;
	bool no_bufs = false;
	uint64_t processed_contexts = 0;

	while (true) {
		size_t writeable_amount;
		size_t needed;
		enum dplane_op_e ctx_op;

		frr_with_mutex (&fnc->obuf_mutex) {
			writeable_amount = STREAM_WRITEABLE(fnc->obuf);
		}

		/*
		 * No space available yet. Legacy contexts write exactly one
		 * frame, which one DPLANE_FPM_NL_BUF_SIZE of room already proves
		 * will fit, so that threshold is left as it was. Only nhg-fib
		 * contexts write batches and need the wider window.
		 */
		needed = fnc->use_nhg_fib ? DPLANE_FPM_NL_MIN_WRITEABLE
					  : DPLANE_FPM_NL_BUF_SIZE;
		if (writeable_amount < needed) {
			no_bufs = true;
			break;
		}

		/*
		 * A context held over from a previous run is the head of the
		 * queue: retry it before anything newer, or operations on the
		 * same prefix would be reordered.
		 *
		 * Only the nhg-fib path ever fills the slot, so the flag test is
		 * redundant on its own — it is here so the legacy path reads as
		 * the plain dequeue it has always been.
		 */
		if (fnc->use_nhg_fib && fnc->stashed_ctx != NULL) {
			ctx = fnc->stashed_ctx;
			fnc->stashed_ctx = NULL;
		} else {
			/* Dequeue next item or quit processing. */
			frr_with_mutex (&fnc->ctxqueue_mutex) {
				ctx = dplane_ctx_dequeue(&fnc->ctxqueue);
			}
		}
		if (ctx == NULL)
			break;

		/*
		 * -1 means the context did not fit in the output buffer, so
		 * nothing of it was emitted and no state moved: it is wholly
		 * retryable. Hold it in the stash and stop draining rather than
		 * telling zebra the route failed — zebra treats an install
		 * failure as terminal (rib_process_result() has no retry), so a
		 * transient buffer shortage would otherwise cost the route.
		 *
		 * This terminates. The batch is bounded (FPM_NHG_PENDING_DELS_MAX
		 * plus one route frame plus this context's own NEWs), the check
		 * that rejected it is against free space in the 8MiB obuf, and
		 * fpm_write() grows that space as the peer reads. A batch that
		 * could never fit is failed inside fpm_nl_enqueue() instead of
		 * returning -1, so it never reaches this slot. If the peer stops
		 * reading altogether, t_wedged (armed below, since no_bufs is
		 * set) forces a reconnect and full resync.
		 *
		 * Gated on use_nhg_fib and on the route ops: the legacy path can
		 * also return -1 and has always ignored it, and only a route
		 * context builds a batch, so nothing else is worth holding.
		 */
		ctx_op = dplane_ctx_get_op(ctx);
		if (fnc->socket != -1 && fpm_nl_enqueue(fnc, ctx) == -1 &&
		    fnc->use_nhg_fib &&
		    (ctx_op == DPLANE_OP_ROUTE_INSTALL ||
		     ctx_op == DPLANE_OP_ROUTE_UPDATE ||
		     ctx_op == DPLANE_OP_ROUTE_DELETE)) {
			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug("%s: output buffer full, holding ctx for retry (%pFX table %u)",
					   __func__, dplane_ctx_get_dest(ctx),
					   dplane_ctx_get_table(ctx));
			fnc->stashed_ctx = ctx;
			no_bufs = true;
			break;
		}

		/* Account the processed entries. */
		processed_contexts++;

		dplane_provider_enqueue_out_ctx(fnc->prov, ctx);
	}

	/*
	 * End of drain: flush the DELs deferred by the contexts just processed.
	 * They are only carried until the next batch needs them at its head, so
	 * without this they could sit here for as long as no further nhg-fib
	 * context arrives. Bounding that lag is all this does — correctness
	 * never depended on it.
	 */
	if (fnc->use_nhg_fib && fnc->socket != -1) {
		frr_with_mutex (&fnc->obuf_mutex) {
			fpm_nhg_pending_dels_flush_locked(fnc, __func__);
		}
	}

	/* Update count of processed contexts */
	atomic_fetch_add_explicit(&fnc->counters.dplane_contexts,
				  processed_contexts, memory_order_relaxed);

	/* Re-schedule if we ran out of buffer space */
	if (no_bufs) {
		if (processed_contexts)
			event_add_event(fnc->fthread->master, fpm_process_queue, fnc, 0,
					&fnc->t_dequeue);
		else
			event_add_timer_msec(fnc->fthread->master, fpm_process_queue, fnc, 10,
					     &fnc->t_dequeue);
		event_add_timer(fnc->fthread->master, fpm_process_wedged, fnc,
				DPLANE_FPM_NL_WEDGIE_TIME, &fnc->t_wedged);
	} else
		event_cancel(&fnc->t_wedged);

	/*
	 * Let the dataplane thread know if there are items in the
	 * output queue to be processed. Otherwise they may sit
	 * until the dataplane thread gets scheduled for new,
	 * unrelated work.
	 */
	if (processed_contexts)
		dplane_provider_work_ready();
}

/**
 * Handles external (e.g. CLI, data plane or others) events.
 */
static void fpm_process_event(struct event *t)
{
	struct fpm_nl_ctx *fnc = EVENT_ARG(t);
	enum fpm_nl_events event = EVENT_VAL(t);

	switch (event) {
	case FNE_DISABLE:
		zlog_info("%s: manual FPM disable event", __func__);
		fnc->disabled = true;
		atomic_fetch_add_explicit(&fnc->counters.user_disables, 1,
					  memory_order_relaxed);

		/* Call reconnect to disable timers and clean up context. */
		fpm_reconnect(fnc);
		break;

	case FNE_RECONNECT:
		zlog_info("%s: manual FPM reconnect event", __func__);
		fnc->disabled = false;
		atomic_fetch_add_explicit(&fnc->counters.user_configures, 1,
					  memory_order_relaxed);
		fpm_reconnect(fnc);
		break;

	case FNE_RESET_COUNTERS:
		zlog_info("%s: manual FPM counters reset event", __func__);
		memset(&fnc->counters, 0, sizeof(fnc->counters));
		break;

	case FNE_TOGGLE_NHG:
		zlog_info("%s: toggle next hop groups support", __func__);
		fnc->use_nhg = !fnc->use_nhg;
		if (fnc->use_nhg)
			fnc->use_nhg_fib = false;
		fpm_reconnect(fnc);
		break;

	case FNE_TOGGLE_NHG_FIB:
		zlog_info("%s: toggle RIB/FIB next hop groups support",
			  __func__);
		fnc->use_nhg_fib = !fnc->use_nhg_fib;
		if (fnc->use_nhg_fib)
			fnc->use_nhg = false;
		fpm_reconnect(fnc);
		break;

	case FNE_INTERNAL_RECONNECT:
		fpm_reconnect(fnc);
		break;

	case FNE_NHG_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: next hop groups walk finished",
				   __func__);
		break;
	case FNE_RIB_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: RIB walk finished", __func__);
		break;
	case FNE_RMAC_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: RMAC walk finished", __func__);
		break;
	case FNE_LSP_FINISHED:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: LSP walk finished", __func__);
		break;
	}
}

/*
 * Data plane functions.
 */
static int fpm_nl_start(struct zebra_dplane_provider *prov)
{
	struct fpm_nl_ctx *fnc;

	fnc = dplane_provider_get_data(prov);
	fnc->fthread = frr_pthread_new(NULL, prov_name, prov_name);
	assert(frr_pthread_run(fnc->fthread, NULL) == 0);
	fnc->ibuf = stream_new(DPLANE_FPM_NL_BUF_SIZE);
	fnc->obuf = stream_new(DPLANE_FPM_NL_BUF_SIZE * 128);
	pthread_mutex_init(&fnc->obuf_mutex, NULL);
	fnc->socket = -1;
	fnc->disabled = true;
	fnc->prov = prov;
	dplane_ctx_q_init(&fnc->ctxqueue);
	pthread_mutex_init(&fnc->ctxqueue_mutex, NULL);

	/* Set default values. */
	fnc->use_nhg = true;
	fnc->use_route_replace = true;

	return 0;
}

static int fpm_nl_finish_early(struct fpm_nl_ctx *fnc)
{
	bool cleaning_p = false;

	/* This is being called in the main pthread: ensure we don't deadlock
	 * with similar code that may be run in the FPM pthread.
	 */
	if (!atomic_compare_exchange_strong_explicit(
		    &fpm_cleaning_up, &cleaning_p, true, memory_order_seq_cst,
		    memory_order_seq_cst))
		return 0;

	/* Disable all events and close socket. */
	event_cancel(&fnc->t_lspreset);
	event_cancel(&fnc->t_lspwalk);
	event_cancel(&fnc->t_nhgreset);
	event_cancel(&fnc->t_nhgwalk);
	event_cancel(&fnc->t_ribreset);
	event_cancel(&fnc->t_ribwalk);
	event_cancel(&fnc->t_rmacreset);
	event_cancel(&fnc->t_rmacwalk);
	event_cancel(&fnc->t_event);
	event_cancel(&fnc->t_nhg);
	event_cancel(&fnc->t_nhg_fib);
	event_cancel_async(fnc->fthread->master, &fnc->t_read, NULL);
	event_cancel_async(fnc->fthread->master, &fnc->t_write, NULL);
	event_cancel_async(fnc->fthread->master, &fnc->t_connect, NULL);

	if (fnc->socket != -1) {
		close(fnc->socket);
		fnc->socket = -1;
	}

	/* Reset the barrier value */
	cleaning_p = true;
	atomic_compare_exchange_strong_explicit(
		&fpm_cleaning_up, &cleaning_p, false, memory_order_seq_cst,
		memory_order_seq_cst);

	return 0;
}

static int fpm_nl_finish_late(struct fpm_nl_ctx *fnc)
{
	/* Stop the running thread. */
	frr_pthread_stop(fnc->fthread, NULL);

	/* Free all allocated resources. */
	pthread_mutex_destroy(&fnc->obuf_mutex);
	pthread_mutex_destroy(&fnc->ctxqueue_mutex);
	/*
	 * Destroy the NHG tables themselves, not just their contents: this is
	 * the final teardown. It runs after frr_pthread_stop() above, so no
	 * writer is left and the already destroyed obuf_mutex is not needed.
	 */
	fpm_nhg_tables_fini(&fnc->nhg_tables);
	fpm_nhg_del_queue_free(&fnc->pending_dels);
	/* Runs after frr_pthread_stop(), so nothing can be racing the slot. */
	if (fnc->stashed_ctx != NULL)
		dplane_ctx_fini(&fnc->stashed_ctx);
	stream_free(fnc->ibuf);
	stream_free(fnc->obuf);
	free(gfnc);
	gfnc = NULL;

	return 0;
}

static int fpm_nl_finish(struct zebra_dplane_provider *prov, bool early)
{
	struct fpm_nl_ctx *fnc;

	fnc = dplane_provider_get_data(prov);
	if (early)
		return fpm_nl_finish_early(fnc);

	return fpm_nl_finish_late(fnc);
}

static int fpm_nl_process(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	int counter, limit;
	uint64_t cur_queue = 0, peak_queue = 0, stored_peak_queue;

	fnc = dplane_provider_get_data(prov);
	limit = dplane_provider_get_work_limit(prov);

	frr_with_mutex (&fnc->ctxqueue_mutex) {
		cur_queue = dplane_ctx_queue_count(&fnc->ctxqueue);
	}

	if (cur_queue >= (uint64_t)limit) {
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: Already at a limit(%" PRIu64
				   ") of internal work, hold off",
				   __func__, cur_queue);
		limit = 0;
	} else {
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: current queue is %" PRIu64
				   ", limiting to lesser amount of %" PRIu64,
				   __func__, cur_queue, limit - cur_queue);
		limit -= cur_queue;
	}

	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (ctx == NULL)
			break;

		/*
		 * Skip all notifications if not connected, we'll walk the RIB
		 * anyway.
		 */
		if (fnc->socket != -1 && fnc->connecting == false) {
			enum dplane_op_e op = dplane_ctx_get_op(ctx);

			/*
			 * Skip multicast routes: MRIB routes flow through
			 * the dataplane pipeline but should not be sent to
			 * FPM. Without this filter, MRIB ROUTE_DELETE events
			 * can remove valid unicast routes from APP_DB.
			 */
			if ((op == DPLANE_OP_ROUTE_DELETE ||
			     op == DPLANE_OP_ROUTE_INSTALL ||
			     op == DPLANE_OP_ROUTE_UPDATE) &&
			    dplane_ctx_get_safi(ctx) == SAFI_MULTICAST)
				goto skip;

			frr_with_mutex (&fnc->ctxqueue_mutex) {
				dplane_ctx_enqueue_tail(&fnc->ctxqueue, ctx);
				cur_queue =
					dplane_ctx_queue_count(&fnc->ctxqueue);
			}

			if (peak_queue < cur_queue)
				peak_queue = cur_queue;
			continue;
		}
skip:
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	/* Update peak queue length, if we just observed a new peak */
	stored_peak_queue = atomic_load_explicit(
		&fnc->counters.ctxqueue_len_peak, memory_order_relaxed);
	if (stored_peak_queue < peak_queue)
		atomic_store_explicit(&fnc->counters.ctxqueue_len_peak,
				      peak_queue, memory_order_relaxed);

	if (cur_queue > 0)
		event_add_event(fnc->fthread->master, fpm_process_queue, fnc, 0,
				&fnc->t_dequeue);

	/* Ensure dataplane thread is rescheduled if we hit the work limit */
	if (counter >= limit)
		dplane_provider_work_ready();

	return 0;
}

static int fpm_nl_new(struct event_loop *tm)
{
	struct zebra_dplane_provider *prov = NULL;
	int rv;

	gfnc = calloc(1, sizeof(*gfnc));
	gfnc->fib_log_level = FIB_LOG_LEVEL_INFO; /* Default: INFO */
	gfnc->use_nhg_fib = false;
	fpm_nhg_tables_init(&gfnc->nhg_tables);
	fib_frr_set_log_level(gfnc->fib_log_level);
	zlog_info("%s: FIB log level initialized to %d (INFO)", __func__, gfnc->fib_log_level);
	rv = dplane_provider_register(prov_name, DPLANE_PRIO_POSTPROCESS,
				      DPLANE_PROV_FLAG_THREADED, fpm_nl_start,
				      fpm_nl_process, fpm_nl_finish, gfnc,
				      &prov);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s register status: %d", prov_name, rv);

	install_node(&fpm_node);
	install_element(ENABLE_NODE, &fpm_show_status_cmd);
	install_element(ENABLE_NODE, &fpm_show_counters_cmd);
	install_element(ENABLE_NODE, &fpm_show_counters_json_cmd);
	install_element(ENABLE_NODE, &fpm_show_nhg_fib_cmd);
	install_element(ENABLE_NODE, &fpm_show_fib_log_level_cmd);
	install_element(ENABLE_NODE, &fpm_reset_counters_cmd);
	install_element(CONFIG_NODE, &fpm_set_address_cmd);
	install_element(CONFIG_NODE, &no_fpm_set_address_cmd);
	install_element(CONFIG_NODE, &fpm_use_nhg_cmd);
	install_element(CONFIG_NODE, &no_fpm_use_nhg_cmd);
	install_element(CONFIG_NODE, &fpm_use_nhg_fib_cmd);
	install_element(CONFIG_NODE, &no_fpm_use_nhg_fib_cmd);
	install_element(CONFIG_NODE, &fpm_use_route_replace_cmd);
	install_element(CONFIG_NODE, &no_fpm_use_route_replace_cmd);
	install_element(CONFIG_NODE, &fpm_set_fib_log_level_cmd);
	install_element(CONFIG_NODE, &no_fpm_set_fib_log_level_cmd);

	return 0;
}

/*
 * FRR-compatible callback to forward logs from FIB to FRR's logging system.
 */
static void frr_log_forwarder(int level,
                              const char *file,
                              int line,
                              const char *func,
                              const char *fmt,
                              va_list args)
{
    int current_log_level = fib_frr_get_log_level();

    /*
     * We would skip logging message if
     * level is below current log level and debug zebra fpm is not enabled
     */
    if (level < current_log_level &&  !IS_ZEBRA_DEBUG_FPM) {
        return;
    }

    /*
     * Direct stderr — FRR convention for FIB path debugging
     * We can't use FRR's zlog here because no API for forwarding va_list, and
     * we want to preserve the original log level and formatting as much as possible.
     */
    fprintf(stderr, "[ZEBRA:FIB] %s:%d (%s) ", file, line, func);
    va_list args_copy;
    va_copy(args_copy, args);
    vfprintf(stderr, fmt, args_copy);
    va_end(args_copy);
    fprintf(stderr, "\n");
    fflush(stderr);
}

/* Called during FRR daemon initialization */
static void fib_init_logging(void) {
    /* Register callback BEFORE any fib_LOG() calls */
    fib_frr_register_callback(frr_log_forwarder);

    zlog_info("%s : FIB logging callback registered, log level will be applied after configuration load",
			  __func__);
}

static int fpm_nl_init(void)
{
	hook_register(frr_late_init, fpm_nl_new);
	fib_init_logging();
	return 0;
}

FRR_MODULE_SETUP(
	.name = "dplane_fpm_sonic",
	.version = "0.0.1",
	.description = "Data plane plugin for FPM using netlink.",
	.init = fpm_nl_init,
);
