#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <time.h>
#include "io_vfs_cache.skel.h"
#include "io_vfs_cache.h"

static volatile int keep_running = 1;

// 信号处理函数
void signal_handler(int signum) {
    keep_running = 0;
}

// 事件处理函数
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct stats *s = data;
    if (s) {
        // 在这里我们不再直接输出信息，而是将数据存储起来
        // 每秒输出一次统计信息
        // 这里可以添加代码将数据存储到一个全局变量中
    }
}

int main() {
    struct io_vfs_cache_bpf *skel;
    struct perf_buffer *pb;
    int err;
    time_t last_output_time = 0;

    // 注册信号处理函数
    signal(SIGINT, signal_handler);

    // 打开并加载 BPF 程序
    skel = io_vfs_cache_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // 附加 BPF 程序
    err = io_vfs_cache_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("BPF programs attached successfully\n");

    // 创建 perf buffer
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 16, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    // 循环处理事件，直到接收到中断信号
    printf("Monitoring cache statistics...\n");
    while (keep_running) {
        err = perf_buffer__poll(pb, 100); // 每 100 毫秒轮询一次
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }

        // 每秒输出一次统计信息
        time_t current_time = time(NULL);
        if (current_time != last_output_time) {
            last_output_time = current_time;

            // 获取并输出统计信息
            struct stats s = {0};
            unsigned int pid;
            int map_fd = bpf_map__fd(skel->maps.stat_map);

            // 遍历所有 PID 并输出统计信息
            unsigned int next_pid = 0;
            while (bpf_map_get_next_key(map_fd, &next_pid, &pid) == 0) {
                if (bpf_map_lookup_elem(map_fd, &pid, &s) == 0) {
                    double hit_rate = 0.0;
                    double file_hit_rate = 0.0;
                    double anon_hit_rate = 0.0;

                    // 计算总命中率
                    if (s.total > 0) {
                        hit_rate = (double)(s.file_hits + s.anon_hits) / s.total * 100;
                    }

                    // 计算文件缓存命中率
                    if (s.file_hits + s.misses > 0) {
                        file_hit_rate = (double)s.file_hits / (s.file_hits + s.misses) * 100;
                    }

                    // 计算匿名页缓存命中率
                    if (s.anon_hits + s.misses > 0) {
                        anon_hit_rate = (double)s.anon_hits / (s.anon_hits + s.misses) * 100;
                    }

                    // 输出统计信息
                    printf("PID: %u\n", s.pid);
                    printf("  Total Accesses: %lld\n", s.total);
                    printf("  File Cache Hits: %lld (%.2f%%)\n", s.file_hits, file_hit_rate);
                    printf("  Anonymous Page Hits: %lld (%.2f%%)\n", s.anon_hits, anon_hit_rate);
                    printf("  Cache Misses: %lld\n", s.misses);
                    printf("  Mark Buffer Dirty Events: %llu\n", s.mbd);
                    printf("  Overall Cache Hit Rate: %.2f%%\n", hit_rate);
                    printf("----------------------------------------\n");
                }
                next_pid = pid;
            }
        }
    }

cleanup:
    // 清理资源
    perf_buffer__free(pb);
    io_vfs_cache_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}