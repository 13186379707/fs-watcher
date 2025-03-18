#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义用于统计缓存命中和失效的 BPF map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32); // 使用函数名作为 key
    __type(value, u64); // 统计调用次数
} meta_cache_stats SEC(".maps");

// 定义要监控的函数
SEC("kprobe/fuse_getattr")
int BPF_KPROBE(fuse_getattr) {
    u32 key = 1; // 1 表示 fuse_getattr
    u64 *count = bpf_map_lookup_elem(&meta_cache_stats, &key);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        bpf_map_update_elem(&meta_cache_stats, &key, &init_val, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/fuse_invalidate_attr")
int BPF_KPROBE(fuse_invalidate_attr) {
    u32 key = 2; // 2 表示 fuse_invalidate_attr
    u64 *count = bpf_map_lookup_elem(&meta_cache_stats, &key);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        bpf_map_update_elem(&meta_cache_stats, &key, &init_val, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/fuse_lookup")
int BPF_KPROBE(fuse_lookup) {
    u32 key = 3; // 3 表示 fuse_lookup
    u64 *count = bpf_map_lookup_elem(&meta_cache_stats, &key);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        bpf_map_update_elem(&meta_cache_stats, &key, &init_val, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/fuse_invalidate_entry_cache")
int BPF_KPROBE(fuse_invalidate_entry_cache) {
    u32 key = 4; // 4 表示 fuse_invalidate_entry_cache
    u64 *count = bpf_map_lookup_elem(&meta_cache_stats, &key);
    if (count) {
        (*count)++;
    } else {
        u64 init_val = 1;
        bpf_map_update_elem(&meta_cache_stats, &key, &init_val, BPF_ANY);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";