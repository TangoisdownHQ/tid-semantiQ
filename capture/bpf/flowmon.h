/* flowmon.h — the flow-event struct shared by the eBPF program and its
 * userspace loader, plus the one function that turns an event into a line of
 * the JSON contract `semantiq.py monitor` reads (capture/bpf/README.md).
 *
 * Keeping the JSON formatter here, rather than in the loader, is deliberate:
 * it is the single place the C producer and the Python consumer could
 * silently disagree on the wire format, so it is isolated to be unit-tested
 * on its own (capture/bpf/selftest.c, exercised by tests/test_ebpf.py) with
 * an ordinary compiler — no kernel, no libbpf, no root. The eBPF side pulls
 * in only the struct; the formatter (which needs stdio) is compiled out
 * there by the __bpf__ guard clang sets for the BPF target.
 */
#ifndef SEMANTIQ_FLOWMON_H
#define SEMANTIQ_FLOWMON_H

#ifdef __bpf__
/* vmlinux.h has already supplied the __uN types on the BPF target. */
#else
#include <linux/types.h>
#endif

#define FLOWMON_DIR_EGRESS 0 /* local -> remote */
#define FLOWMON_DIR_INGRESS 1 /* remote -> local */

/* One finished burst. Ports and the timestamp are stored host-order and in
 * nanoseconds respectively by the kernel program, so the formatter below is
 * trivial and endian-independent. Addresses stay network-order (big-endian),
 * which is exactly dotted-quad byte order, so no conversion is needed. */
struct flow_event {
	__u64 ts_ns;   /* kernel monotonic time of the burst's first packet */
	__u64 bytes;   /* bytes in the burst */
	__u32 saddr;   /* IPv4, network order */
	__u32 daddr;   /* IPv4, network order */
	__u32 packets; /* packets in the burst */
	__u16 sport;   /* host order */
	__u16 dport;   /* host order */
	__u8 proto;    /* IPPROTO_TCP (6) or IPPROTO_UDP (17) */
	__u8 dir;      /* FLOWMON_DIR_* */
};

#ifndef __bpf__
#include <stdio.h>

/* Render an event as one line of the JSON contract. Returns the number of
 * bytes written (excluding the NUL), or a negative value on truncation —
 * the caller treats a short buffer as a dropped record rather than emitting
 * a half line that `read_jsonl_flows` would reject anyway. */
static inline int flow_event_to_json(char *buf, int len,
				     const struct flow_event *e)
{
	const unsigned char *s = (const unsigned char *)&e->saddr;
	const unsigned char *d = (const unsigned char *)&e->daddr;
	double ts = (double)e->ts_ns / 1e9;
	const char *proto = e->proto == 17 ? "udp" : "tcp";
	const char *dir = e->dir == FLOWMON_DIR_INGRESS ? "ingress" : "egress";
	int n = snprintf(
		buf, (size_t)len,
		"{\"ts\": %.6f, \"proto\": \"%s\", "
		"\"saddr\": \"%u.%u.%u.%u\", \"daddr\": \"%u.%u.%u.%u\", "
		"\"sport\": %u, \"dport\": %u, \"dir\": \"%s\", "
		"\"bytes\": %llu, \"packets\": %u}\n",
		ts, proto,
		s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3],
		(unsigned)e->sport, (unsigned)e->dport, dir,
		(unsigned long long)e->bytes, (unsigned)e->packets);
	if (n < 0 || n >= len)
		return -1;
	return n;
}
#endif /* __bpf__ */

#endif /* SEMANTIQ_FLOWMON_H */
