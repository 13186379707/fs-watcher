#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include "cache_stat.skel.h"

struct stats {
    __s64 total;  // Total accesses
    __s64 misses; // Cache misses
    __u64 mbd;    // Mark buffer dirty events
};

static volatile int keep_running = 1;

// 事件处理函数
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct stats *s = data;
    if (s) {
        double hit_rate = 0.0;
        if (s->total > 0) {
            hit_rate = (double)(s->total - s->misses) / s->total * 100; // 计算命中率
        }
        printf("Total: %lld, Misses: %lld, Mark Buffer Dirty: %llu, Hit Rate: %.2f%%\n", 
               s->total, s->misses, s->mbd, hit_rate);
    }
}

// 信号处理函数
void signal_handler(int signum) {
    keep_running = 0;
}

int main() {
    struct cache_stat_bpf *obj;
    struct perf_buffer *pb;
    int err;

    // 注册信号处理函数
    signal(SIGINT, signal_handler);

    obj = cache_stat_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = cache_stat_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("BPF programs attached successfully\n");

    // 创建 perf buffer
    struct perf_buffer_opts pb_opts = {
        .sz = sizeof(pb_opts),
    };

    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 16, handle_event, NULL, NULL, &pb_opts);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    // 循环处理事件，直到接收到中断信号
    while (keep_running) {
        perf_buffer__poll(pb, 100);
    }

cleanup:
    cache_stat_bpf__destroy(obj);
    return 0;
}

