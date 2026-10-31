/* flowmon.bpf.c — in-kernel per-flow burst accounting for `semantiq monitor`.
 *
 * Two hooks, one object, shared maps:
 *   SEC("xdp")       flowmon_xdp  — INGRESS, the line-rate fast path.
 *   SEC("tc")        flowmon_tc   — EGRESS, because XDP cannot see egress and
 *                                   the outbound callback is the whole point
 *                                   of beacon detection.
 *
 * Each packet is parsed just far enough for its 5-tuple and length, its flow
 * is looked up in a hash map, and the running burst is extended — or, if the
 * flow has been idle longer than GAP_NS, the finished burst is pushed to a
 * ring buffer as a `struct flow_event` and a new one begun. The userspace
 * loader (flowmon.c) drains the ring buffer, renders each event as one JSON
 * line (flow_event_to_json in flowmon.h), and also sweeps the map for flows
 * idle past the gap so a flow that goes quiet still reports its last burst.
 *
 * This file cannot be compiled without a BPF toolchain (clang -target bpf,
 * vmlinux.h, libbpf) and is not exercised by the test suite — the tested,
 * load-bearing piece is the JSON contract in flowmon.h. Build with the
 * Makefile beside it, on the host you will run it on.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "flowmon.h"

char LICENSE[] SEC("license") = "GPL"; /* required to call GPL-only helpers */

/* Close a burst after this much idle on a flow — the kernel-side mirror of
 * the pcap burst gap. 1s in nanoseconds. Override at load time if needed. */
#define GAP_NS (1000ULL * 1000ULL * 1000ULL)

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u8 dir;
};

struct flow_state {
	__u64 first_ns;
	__u64 last_ns;
	__u64 bytes;
	__u32 packets;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1 << 16);
	__type(key, struct flow_key);
	__type(value, struct flow_state);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MB of pending events */
} events SEC(".maps");

static __always_inline void emit(const struct flow_key *k,
				 const struct flow_state *st)
{
	struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return; /* ring full: drop this record. Userspace reports the
			 * ringbuf drop counter so the loss is never silent. */
	e->ts_ns = st->first_ns;
	e->bytes = st->bytes;
	e->saddr = k->saddr;
	e->daddr = k->daddr;
	e->packets = st->packets;
	e->sport = k->sport;
	e->dport = k->dport;
	e->proto = k->proto;
	e->dir = k->dir;
	bpf_ringbuf_submit(e, 0);
}

/* Shared accounting. `data`/`data_end` bound the L3 frame (IP header first);
 * both hooks hand us those as plain pointers, so one body serves both. */
static __always_inline void account(void *data, void *data_end, __u8 dir,
				    __u32 wire_len)
{
	struct iphdr *ip = data;
	if ((void *)(ip + 1) > data_end)
		return;
	if (ip->version != 4)
		return; /* IPv6 is a documented follow-on, not handled yet. */
	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return;

	__u32 ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip))
		return;
	void *l4 = (void *)ip + ihl;
	__u16 sport = 0, dport = 0;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *t = l4;
		if ((void *)(t + 1) > data_end)
			return;
		sport = bpf_ntohs(t->source);
		dport = bpf_ntohs(t->dest);
	} else {
		struct udphdr *u = l4;
		if ((void *)(u + 1) > data_end)
			return;
		sport = bpf_ntohs(u->source);
		dport = bpf_ntohs(u->dest);
	}

	struct flow_key k = {
		.saddr = ip->saddr,
		.daddr = ip->daddr,
		.sport = sport,
		.dport = dport,
		.proto = ip->protocol,
		.dir = dir,
	};
	__u64 now = bpf_ktime_get_ns();
	struct flow_state *st = bpf_map_lookup_elem(&flows, &k);
	if (st && now - st->last_ns <= GAP_NS) {
		st->last_ns = now;
		st->bytes += wire_len;
		st->packets += 1;
		return;
	}
	if (st) {
		emit(&k, st); /* gap exceeded: flush the finished burst first */
	}
	struct flow_state fresh = {
		.first_ns = now, .last_ns = now,
		.bytes = wire_len, .packets = 1,
	};
	bpf_map_update_elem(&flows, &k, &fresh, BPF_ANY);
}

SEC("xdp")
int flowmon_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IP))
		account(eth + 1, data_end, FLOWMON_DIR_INGRESS,
			data_end - (void *)(eth + 1));
	return XDP_PASS; /* monitor only: never drop, never alter traffic */
}

SEC("tc")
int flowmon_tc(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto == bpf_htons(ETH_P_IP))
		account(eth + 1, data_end, FLOWMON_DIR_EGRESS,
			data_end - (void *)(eth + 1));
	return TC_ACT_OK; /* monitor only */
}
