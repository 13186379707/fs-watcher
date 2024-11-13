#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义结构体存储统计信息
struct stats {
    __s64 total;  // Total accesses
    __s64 misses; // Cache misses
    __u64 mbd;    // Mark buffer dirty events
};

// 定义哈希表来存储统计信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stats);
} stat_map SEC(".maps");

// 定义 perf buffer 映射，用于传递事件到用户态
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// fentry 入口
SEC("fentry/add_to_page_cache_lru")
int BPF_PROG(fentry_add_to_page_cache_lru) {
    u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&stat_map, &key);
    if (!s) {
        struct stats initial = {0, 0, 0};
        bpf_map_update_elem(&stat_map, &key, &initial, 0);
        s = &initial;
    }
    __sync_fetch_and_add(&s->misses, 1);
    bpf_perf_event_output(ctx, &events, 0, s, sizeof(*s));
    return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(fentry_mark_page_accessed) {
    u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&stat_map, &key);
    if (!s) return 0;
    __sync_fetch_and_add(&s->total, 1);
    return 0;
}



SEC("fentry/mark_buffer_dirty")
int BPF_PROG(fentry_mark_buffer_dirty) {
    u32 key = 0;
    struct stats *s = bpf_map_lookup_elem(&stat_map, &key);
    if (!s) return 0;
    __sync_fetch_and_add(&s->mbd, 1); // Increment mark buffer dirty events
    return 0;
}

