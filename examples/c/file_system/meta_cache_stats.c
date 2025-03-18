#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "meta_cache_stats.skel.h"

// 打印缓存命中率
void print_cache_hit_rate(struct bpf_map *map) {
    unsigned int key;
    unsigned long long value;
    unsigned long long hit_count = 0, miss_count = 0;

    // 遍历 BPF map，获取统计信息
    for (key = 1; key <= 4; key++) {
        if (bpf_map_lookup_elem(bpf_map__fd(map), &key, &value) == 0) {
            if (key == 1 || key == 3) {
                hit_count += value; // fuse_getattr 和 fuse_lookup 是缓存命中
            } else if (key == 2 || key == 4) {
                miss_count += value; // fuse_invalidate_attr 和 fuse_invalidate_entry_cache 是缓存失效
            }
        }
    }

    // 计算缓存命中率
    if (hit_count + miss_count > 0) {
        double hit_rate = (double)hit_count / (hit_count + miss_count) * 100;
        printf("Metadata Cache Hit Rate: %.2f%%\n", hit_rate);
    } else {
        printf("No metadata cache operations recorded.\n");
    }
}

int main(int argc, char **argv) {
    struct meta_cache_stats_bpf *skel;
    int err;

    // 加载 BPF 程序
    skel = meta_cache_stats_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序到 kprobe
    err = meta_cache_stats_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Monitoring metadata cache hit rate...\n");

    // 每隔 2 秒打印一次缓存命中率
    while (1) {
        sleep(2);
        print_cache_hit_rate(skel->maps.meta_cache_stats);
    }

cleanup:
    meta_cache_stats_bpf__destroy(skel);
    return 0;
}