/* selftest.c — proves the C producer and the Python consumer agree on the
 * JSON contract, with an ordinary compiler (no kernel, no libbpf, no root).
 *
 * It builds a couple of flow_events by hand and prints them with the very
 * function flowmon.c uses, flow_event_to_json. tests/test_ebpf.py compiles
 * and runs this, then feeds the output back through `read_jsonl_flows` and
 * checks the round trip — so a change to the struct or the formatter that
 * would break the live feed fails a test instead of shipping.
 *
 *   cc -I. selftest.c -o selftest && ./selftest
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "flowmon.h"

int main(void)
{
	/* 10.0.0.5:51000 -> 203.0.113.9:443, egress, one 256-byte burst.
	 * Addresses are network-order (big-endian) = dotted-quad byte order. */
	struct flow_event egress = {
		.ts_ns = 1700000000ULL * 1000000000ULL + 500000000ULL,
		.bytes = 256,
		.saddr = (10) | (0 << 8) | (0 << 16) | ((unsigned)5 << 24),
		.daddr = (203) | (0 << 8) | (113 << 16) | ((unsigned)9 << 24),
		.packets = 1,
		.sport = 51000,
		.dport = 443,
		.proto = 6,
		.dir = FLOWMON_DIR_EGRESS,
	};
	struct flow_event ingress = {
		.ts_ns = 1700000000ULL * 1000000000ULL + 600000000ULL,
		.bytes = 1400,
		.saddr = (203) | (0 << 8) | (113 << 16) | ((unsigned)9 << 24),
		.daddr = (10) | (0 << 8) | (0 << 16) | ((unsigned)5 << 24),
		.packets = 3,
		.sport = 443,
		.dport = 51000,
		.proto = 17,
		.dir = FLOWMON_DIR_INGRESS,
	};

	char line[256];
	if (flow_event_to_json(line, sizeof(line), &egress) > 0)
		fputs(line, stdout);
	if (flow_event_to_json(line, sizeof(line), &ingress) > 0)
		fputs(line, stdout);
	return 0;
}
