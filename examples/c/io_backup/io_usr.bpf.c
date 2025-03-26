#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义全局变量来存储统计信息
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} read_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} write_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} read_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} write_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} read_latency SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} write_latency SEC(".maps");

// uprobe 监控 read 调用
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:read")
int uprobe__read(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // 获取 read 的参数（读取的数据量）
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    // 更新 read 调用次数和数据量
    u64 *read_cnt = bpf_map_lookup_elem(&read_count, &pid);
    if (read_cnt) {
        (*read_cnt)++;
    } else {
        u64 init_cnt = 1;
        bpf_map_update_elem(&read_count, &pid, &init_cnt, BPF_ANY);
    }

    u64 *bytes = bpf_map_lookup_elem(&read_bytes, &pid);
    if (bytes) {
        (*bytes) += count;
    } else {
        bpf_map_update_elem(&read_bytes, &pid, &count, BPF_ANY);
    }

    // 记录 read 调用的时间戳
    u64 start_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&read_latency, &pid, &start_time, BPF_ANY);

    return 0;
}

// uretprobe 监控 read 返回
SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:read")
int uretprobe__read(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // 获取 read 的返回值（实际读取的数据量）
    ssize_t count = (ssize_t)PT_REGS_RC(ctx);

    /*
    u64 *bytes = bpf_map_lookup_elem(&read_bytes, &pid);
    if (bytes) {
        (*bytes) += count;
    } else {
        bpf_map_update_elem(&read_bytes, &pid, &count, BPF_ANY);
    }
    */

    // 计算 read 的时延
    u64 *start_time = bpf_map_lookup_elem(&read_latency, &pid);
    if (start_time) {
        // 计算响应时间
        u64 end_time = bpf_ktime_get_ns();
        u64 latency = end_time - *start_time;

        bpf_map_update_elem(&read_latency, &pid, &latency, BPF_ANY);
    }

    return 0;
}

// uprobe 监控 write 调用
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:write")
int uprobe__write(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // 获取 write 的参数（写入的数据量）
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    // 更新 write 调用次数和数据量
    u64 *write_cnt = bpf_map_lookup_elem(&write_count, &pid);
    if (write_cnt) {
        (*write_cnt)++;
    } else {
        u64 init_cnt = 1;
        bpf_map_update_elem(&write_count, &pid, &init_cnt, BPF_ANY);
    }

    u64 *bytes = bpf_map_lookup_elem(&write_bytes, &pid);
    if (bytes) {
        (*bytes) += count;
    } else {
        bpf_map_update_elem(&write_bytes, &pid, &count, BPF_ANY);
    }

    // 记录 write 调用的时间戳
    u64 start_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&write_latency, &pid, &start_time, BPF_ANY);

    bpf_printk("write called by PID %d, count: %lu\n", pid, count);
    return 0;
}

// uretprobe 监控 write 返回
SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:write")
int uretprobe__write(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // 获取 write 的返回值（实际写入的数据量）
    ssize_t count = (ssize_t)PT_REGS_RC(ctx);

    /*
    u64 *bytes = bpf_map_lookup_elem(&write_bytes, &pid);
    if (bytes) {
        (*bytes) += count;
    } else {
        bpf_map_update_elem(&write_bytes, &pid, &count, BPF_ANY);
    }
    */

    // 计算 write 的时延
    u64 *start_time = bpf_map_lookup_elem(&write_latency, &pid);
    if (start_time) {
        u64 end_time = bpf_ktime_get_ns();
        u64 latency = end_time - *start_time;

        bpf_map_update_elem(&write_latency, &pid, &latency, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";