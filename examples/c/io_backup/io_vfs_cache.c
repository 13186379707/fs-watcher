#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <time.h>
#include "io_vfs_cache.skel.h"
#include "io_vfs_cache.h"

static volatile bool exiting = false;
static time_t last_output_time = 0;

// 信号处理函数
void sig_handler(int sig) {
    exiting = true;
}

// 事件处理函数
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct stats *s = data;
    if (s) {
        time_t current_time = time(NULL);
        if (current_time != last_output_time) {
            last_output_time = current_time;

            // 获取并输出统计信息
            struct stats s = {0};
            unsigned int pid;
            struct io_vfs_cache_bpf *skel = ctx;
            int map_fd = bpf_map__fd(skel->maps.stat_map);

            // 输出表头
            printf("----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-8s %-16s %-20s %-20s %-16s %-28s %s\n",
                   "PID", "Total Accesses", "File Cache Hits", "Anonymous Hits", 
                   "Cache Misses", "Mark Buffer Dirty", "Overall Hit Rate");

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

                    // 输出统计信息 - 将复合数据分成多个%-格式
                    printf("%-8d %-16lld %-6lld(%-6.2f%%)      %-6lld(%-6.2f%%)      %-16lld %-28llu %-6.2f%%\n",
                           s.pid, s.total, 
                           s.file_hits, file_hit_rate, 
                           s.anon_hits, anon_hit_rate,
                           s.misses, s.mbd, hit_rate);
                }
                next_pid = pid;
            }
        }
    }
}

int main() {
    struct io_vfs_cache_bpf *skel;
    struct perf_buffer *pb;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // 注册信号处理函数
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 打开并加载 BPF 程序
    skel = io_vfs_cache_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序
    err = io_vfs_cache_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 创建 perf buffer
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 16, handle_event, NULL, skel, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    // 循环处理事件，直到接收到中断信号
    while (!exiting) {
        err = perf_buffer__poll(pb, 100); // 每 100 毫秒轮询一次
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    // 清理资源
    perf_buffer__free(pb);
    io_vfs_cache_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}    