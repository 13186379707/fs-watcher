#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义用于统计的数据结构
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, unsigned int); // 使用 unsigned int 作为键
    __type(value, unsigned long long); // 使用 unsigned long long 作为值
} data_cache_hits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, unsigned int); // 使用 unsigned int 作为键
    __type(value, unsigned long long); // 使用 unsigned long long 作为值
} data_cache_misses SEC(".maps");

// 捕获缓存命中事件
SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(mark_page_accessed, struct page *page) {
    unsigned int key = 0; // 使用固定键值
    unsigned long long *value = bpf_map_lookup_elem(&data_cache_hits, &key);
    if (value) {
        (*value)++; // 统计缓存命中次数
    } else {
        unsigned long long init_value = 1;
        bpf_map_update_elem(&data_cache_hits, &key, &init_value, BPF_ANY);
    }
    return 0;
}

// 捕获缓存未命中事件
SEC("kprobe/__page_cache_alloc")
int BPF_KPROBE(page_cache_alloc, gfp_t gfp_mask) {
    unsigned int key = 0; // 使用固定键值
    unsigned long long *value = bpf_map_lookup_elem(&data_cache_misses, &key);
    if (value) {
        (*value)++; // 统计缓存未命中次数
    } else {
        unsigned long long init_value = 1;
        bpf_map_update_elem(&data_cache_misses, &key, &init_value, BPF_ANY);
    }
    return 0;
}

// 捕获文件数据缓存未命中事件
SEC("kprobe/submit_bio")    // 可能会捕获到元数据操作
int BPF_KPROBE(submit_bio, struct bio *bio) {
    unsigned int key = 0; // 使用固定键值
    unsigned long long *value = bpf_map_lookup_elem(&data_cache_misses, &key);
    if (value) {
        (*value)++; // 统计缓存未命中次数
    } else {
        unsigned long long init_value = 1;
        bpf_map_update_elem(&data_cache_misses, &key, &init_value, BPF_ANY);
    }
    return 0;
}

// 捕获文件数据缓存未命中事件
SEC("kprobe/ext4_readpage")
int BPF_KPROBE(ext4_readpage, struct file *file, struct page *page) {
    unsigned int key = 0; // 使用固定键值
    unsigned long long *value = bpf_map_lookup_elem(&data_cache_misses, &key);
    if (value) {
        (*value)++; // 统计缓存未命中次数
    } else {
        unsigned long long init_value = 1;
        bpf_map_update_elem(&data_cache_misses, &key, &init_value, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";