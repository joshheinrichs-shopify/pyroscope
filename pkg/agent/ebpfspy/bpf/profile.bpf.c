#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "profile.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct profile_key_t);
	__type(value, u32);
	__uint(max_entries, PROFILE_MAPS_SIZE);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, PROFILE_MAPS_SIZE);
} stacks SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct profile_bss_args_t);
	__uint(max_entries, 1);
} args SEC(".maps");

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)



SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u32 *val, one = 1, zero = 0;
	struct profile_bss_args_t *arg = bpf_map_lookup_elem(&args, &zero);
	if (!arg) {
		return 0;
	}

	u32 tgid;
	u32 pid;
	if (arg->ns_dev != 0 && arg->ns_ino != 0) {
		struct bpf_pidns_info ns = {};
		if (bpf_get_ns_current_pid_tgid(arg->ns_dev, arg->ns_ino, &ns, sizeof(ns))) {
			return 0;
		}
		tgid = ns.tgid;
		pid = ns.pid;
	} else {
		u64 id = bpf_get_current_pid_tgid();
		tgid = id >> 32;
		pid = id;
	}

	if (pid == 0) {
		return 0;
	}

	if (arg->tgid_filter != 0 && tgid != arg->tgid_filter) {
		return 0;
	}

	struct profile_key_t key = { .pid = tgid };

	bpf_get_current_comm(&key.comm, sizeof(key.comm));

	key.kern_stack = bpf_get_stackid(ctx, &stacks, KERN_STACKID_FLAGS);
	key.user_stack = bpf_get_stackid(ctx, &stacks, USER_STACKID_FLAGS);

	val = bpf_map_lookup_elem(&counts, &key);
	if (val)
		(*val)++;
	else
		bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
	return 0;
}

char _license[] SEC("license") = "GPL"; //todo
