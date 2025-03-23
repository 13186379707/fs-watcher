#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "io_usr.skel.h"

int main(int argc, char **argv) {
    struct io_usr_bpf *skel;
    int read_count_map_fd, write_count_map_fd;
    int read_bytes_map_fd, write_bytes_map_fd;
    int read_latency_map_fd, write_latency_map_fd;
    int err;

    /* 打开BPF应用程序 */
    skel = io_usr_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* 加载并验证BPF程序 */
    err = io_usr_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* 附加跟踪点处理程序 */
    err = io_usr_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // 获取 BPF 映射的文件描述符
    read_count_map_fd = bpf_map__fd(skel->maps.read_count);
    write_count_map_fd = bpf_map__fd(skel->maps.write_count);
    read_bytes_map_fd = bpf_map__fd(skel->maps.read_bytes);
    write_bytes_map_fd = bpf_map__fd(skel->maps.write_bytes);
    read_latency_map_fd = bpf_map__fd(skel->maps.read_latency);
    write_latency_map_fd = bpf_map__fd(skel->maps.write_latency);

    // 定期读取 BPF 映射中的数据
    while (1) {
        pid_t pid, next_pid = 0;
        unsigned long long read_count = 0, write_count = 0;
        unsigned long long read_bytes = 0, write_bytes = 0;
        unsigned long long read_latency = 0, write_latency = 0;

        // 遍历 read_count 映射
        while (bpf_map_get_next_key(read_count_map_fd, &next_pid, &pid) == 0) {
            bpf_map_lookup_elem(read_count_map_fd, &pid, &read_count);
            bpf_map_lookup_elem(read_bytes_map_fd, &pid, &read_bytes);
            bpf_map_lookup_elem(read_latency_map_fd, &pid, &read_latency);

            printf("PID %-5d: read_count = %-5llu read_bytes = %-10llu read_latency(ns) = %-10llu\n",
                   pid, read_count, read_bytes, read_latency);

            next_pid = pid;
        }

        // 遍历 write_count 映射
        next_pid = 0;
        while (bpf_map_get_next_key(write_count_map_fd, &next_pid, &pid) == 0) {
            bpf_map_lookup_elem(write_count_map_fd, &pid, &write_count);
            bpf_map_lookup_elem(write_bytes_map_fd, &pid, &write_bytes);
            bpf_map_lookup_elem(write_latency_map_fd, &pid, &write_latency);

            printf("PID %-5d: write_count = %-5llu write_bytes = %-10llu write_latency(ns) = %-10llu\n",
                   pid, write_count, write_bytes, write_latency);

            next_pid = pid;
        }

        // 计算读写比例
        if (read_count > 0 && write_count > 0) {
            double read_write_ratio = (double)read_count / write_count;
            printf("Read/Write Ratio: %.2f\n", read_write_ratio);
        }

        // 计算读写速率（假设间隔为 1 秒）
        sleep(1);
    }

/* 卸载BPF程序 */
cleanup:
    io_usr_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}