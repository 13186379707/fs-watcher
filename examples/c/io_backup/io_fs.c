#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "io_fs.skel.h"
#include "io_fs.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

// 环形缓冲区回调（输出统计结果）
static int handle_event(void *ctx, void *data, size_t len) {
    const struct event *e = data;
    if (e->read_count || e->write_count || e->read_psize || e->write_psize || e->metadata_reads || e->metadata_writes 
        || e->metadata_reads_size || e->metadata_writes_size || e->dirty_page) {
        printf("[1s] Data(R/W): %-6llu/%-6llu | DataSize(R/W): %-10llu/%-10llu | Metadata(R/W): %-6llu/%-6llu | MetadataSize(R/W): %-10llu/%-10llu | DirtyPage: %-6llu\n",
           e->read_count, e->write_count,
           e->read_psize, e->write_psize,
           e->metadata_reads, e->metadata_writes,
           e->metadata_reads_size, e->metadata_writes_size,
           e->dirty_page);
    }
    
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct io_fs_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 加载并附加BPF程序
    skel = io_fs_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    err = io_fs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    // 设置环形缓冲区回调
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Monitoring ext4 file operations. Press Ctrl+C to stop.\n");
    while (!exiting) {
        // 主动触发统计（每秒一次）
        err = ring_buffer__poll(rb, 1000 /* timeout_ms */);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    io_fs_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}