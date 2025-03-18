#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "data_cache_stats.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    //return vfprintf(stderr, format, args);    // 不显示调式信息
    return 0;
}

// 计算命中率
double calculate_hit_rate(unsigned long long hits, unsigned long long misses) {
    if (hits + misses == 0) {
        return 0.0; // 避免除以零
    }
    return (double)hits / (hits + misses);
}

int main(int argc, char **argv) {
    struct data_cache_stats_bpf *skel;
    int err;

    // 设置 libbpf 日志回调函数
    libbpf_set_print(libbpf_print_fn);

    // 打开并加载 BPF 程序
    skel = data_cache_stats_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序到内核探针
    err = data_cache_stats_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("eBPF program loaded and attached successfully\n");

    // 定期读取统计数据并计算命中率
    while (1) {
        sleep(1);

        // 读取缓存命中次数
        unsigned int key = 0;
        unsigned long long hits = 0, misses = 0;
        bpf_map__lookup_elem(skel->maps.data_cache_hits, &key, sizeof(key), &hits, sizeof(hits), 0);
        bpf_map__lookup_elem(skel->maps.data_cache_misses, &key, sizeof(key), &misses, sizeof(misses), 0);

        // 计算缓存命中率
        double hit_rate = calculate_hit_rate(hits, misses);
        printf("Data cache hit rate: %.2f%% (hits: %llu, misses: %llu)\n", hit_rate * 100, hits, misses);

        // 每次打印数据后，将数据清空，重新采集
        unsigned long long zero = 0;
        bpf_map__update_elem(skel->maps.data_cache_hits, &key, sizeof(key), &zero, sizeof(zero), BPF_ANY);
        bpf_map__update_elem(skel->maps.data_cache_misses, &key, sizeof(key), &zero, sizeof(zero), BPF_ANY);
    }

cleanup:
    // 清理资源
    data_cache_stats_bpf__destroy(skel);
    return -err;
}