#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "io_vfs_cache.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32); // PID
    __type(value, struct stats);
} stat_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static inline void update_stats(void *ctx, u32 pid, bool is_file, bool is_hit) {
    struct stats *s = bpf_map_lookup_elem(&stat_map, &pid);
    if (!s) {
        struct stats initial = {0, 0, 0, 0, 0, 0}; // 初始化所有字段
        bpf_map_update_elem(&stat_map, &pid, &initial, BPF_ANY);
        s = &initial;
    }
    __sync_fetch_and_add(&s->total, 1);
    if (is_hit) {
        if (is_file) {
            __sync_fetch_and_add(&s->file_hits, 1);
        } else {
            __sync_fetch_and_add(&s->anon_hits, 1);
        }
    } else {
        __sync_fetch_and_add(&s->misses, 1);
    }
    s->pid = pid; // 设置 PID
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, s, sizeof(*s));
}

// fentry 入口：mark_page_accessed
SEC("fentry/mark_page_accessed")
int BPF_PROG(fentry_mark_page_accessed, struct page *page) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bool is_file = page->mapping && page->mapping->host;
    update_stats(ctx, pid, is_file, true);
    return 0;
}

// fentry 入口：add_to_page_cache_lru
SEC("fentry/add_to_page_cache_lru")
int BPF_PROG(fentry_add_to_page_cache_lru, struct page *page) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bool is_file = page->mapping && page->mapping->host;
    update_stats(ctx, pid, is_file, false);
    return 0;
}

// fentry 入口：mark_buffer_dirty
SEC("fentry/mark_buffer_dirty")
int BPF_PROG(fentry_mark_buffer_dirty, struct buffer_head *bh) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct stats *s = bpf_map_lookup_elem(&stat_map, &pid);
    if (s) {
        __sync_fetch_and_add(&s->mbd, 1);
    }
    return 0;
}