//go:build ignore

#include "headers/bpf_helpers.h"

struct lpm_key {
	__u32 prefix_len;
	__u32 addr;
};

struct rule_key {
	__u32 group;
	__u16 port;
	__u8 protocol;
	__u8 pad;
};

struct config_value {
	__u32 generation;
	__u32 mode;
};

struct event {
	__u64 cgroup_id;
	__u32 dst_addr;
	__u16 dst_port;
	__u8 protocol;
	__u8 hook;
	__u8 denied;
	__u8 pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u32);
} cidrs_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u32);
} cidrs_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct rule_key);
	__type(value, __u8);
} rules_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct rule_key);
	__type(value, __u8);
} rules_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config_value);
} active_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline __u16 ntohs(__u16 value) {
	return __builtin_bswap16(value);
}

static __always_inline int permitted(__u32 addr, __u8 protocol, __u16 port) {
	__u32 zero = 0;
	struct config_value *cfg = bpf_map_lookup_elem(&active_config, &zero);
	struct lpm_key cidr = { .prefix_len = 32, .addr = addr };
	__u32 *group;
	struct rule_key key = {};
	__u8 *allow;

	if (!cfg)
		return 1;
	group = cfg->generation ? bpf_map_lookup_elem(&cidrs_b, &cidr)
					: bpf_map_lookup_elem(&cidrs_a, &cidr);
	if (!group)
		return 0;
	key.group = *group;
	key.protocol = protocol;
	key.port = port;
	allow = cfg->generation ? bpf_map_lookup_elem(&rules_b, &key)
					: bpf_map_lookup_elem(&rules_a, &key);
	if (allow)
		return 1;
	key.port = 0;
	allow = cfg->generation ? bpf_map_lookup_elem(&rules_b, &key)
					: bpf_map_lookup_elem(&rules_a, &key);
	return allow != 0;
}

static __always_inline int decide(__u32 addr, __u8 protocol, __u16 port, __u8 hook) {
	__u32 zero = 0;
	struct config_value *cfg = bpf_map_lookup_elem(&active_config, &zero);
	int allow = permitted(addr, protocol, port);
	__u32 counter = allow ? (protocol == IPPROTO_UDP ? 1 : 0)
				      : (protocol == IPPROTO_UDP ? 3 : 2);
	__u64 *count = bpf_map_lookup_elem(&counters, &counter);
	if (count)
		__sync_fetch_and_add(count, 1);
	if (!allow) {
		struct event evt = {
			.cgroup_id = bpf_get_current_cgroup_id(),
			.dst_addr = addr,
			.dst_port = port,
			.protocol = protocol,
			.hook = hook,
			.denied = cfg && cfg->mode,
		};
		bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
	}
	return allow || !cfg || !cfg->mode;
}

static __always_inline int audit_or_drop(void) {
	__u32 zero = 0;
	struct config_value *cfg = bpf_map_lookup_elem(&active_config, &zero);
	return !cfg || !cfg->mode;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
	if (ctx->family != AF_INET)
		return 1;
	return decide(ctx->user_ip4, (__u8)ctx->protocol,
		      ntohs((__u16)ctx->user_port), 1);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx) {
	if (ctx->family != AF_INET)
		return 1;
	return decide(ctx->user_ip4, IPPROTO_UDP,
		      ntohs((__u16)ctx->user_port), 2);
}

struct ipv4_header {
	__u8 version_ihl;
	__u8 tos;
	__u16 total_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 checksum;
	__u32 src;
	__u32 dst;
};

SEC("cgroup_skb/egress")
int egress_filter(struct __sk_buff *skb) {
	struct ipv4_header ip = {};
	__u16 port_be = 0;
	__u32 ihl;
	if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
		return 1;
	if ((ip.version_ihl >> 4) != 4)
		return audit_or_drop();
	if (ip.protocol != IPPROTO_TCP && ip.protocol != IPPROTO_UDP)
		return audit_or_drop();
	ihl = (ip.version_ihl & 0x0f) * 4;
	if (ihl < 20 || bpf_skb_load_bytes(skb, ihl + 2, &port_be, sizeof(port_be)) < 0)
		return audit_or_drop();
	return decide(ip.dst, ip.protocol, ntohs(port_be), 3);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
