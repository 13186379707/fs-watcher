#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "system_io.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct system_io);
} system_io SEC(".maps");

SEC("tracepoint/block/block_rq_complete")
int tracepoint__block__block_rq_complete(struct trace_event_raw_block_rq_completion *brc) {
    int index = 0;
    struct system_io *val;

    val = bpf_map_lookup_elem(&system_io, &index);
    if (!val) {
        return 0;
    }

    val->iops_count++;
    val->throughput_count += brc->nr_sector * 512;

    bpf_map_update_elem(&system_io, &index, val, BPF_ANY);

    return 0;
}