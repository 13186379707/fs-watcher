#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "read_cache_time.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {	//记录VFS层时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} FirstTime SEC(".maps");

struct {	//记录内核缓冲层时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} SecondTime SEC(".maps");

/*
struct {	//记录ext4映射层时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} ThirdTime SEC(".maps");
*/

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");	//perf缓冲区


// read请求进入到内核空间，到VFS层结束
SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(void* ctx) {
	u64 start_time = bpf_ktime_get_ns() / 1000;//us
	pid_t pid = bpf_get_current_pid_tgid();

	bpf_trace_printk("sys_enter_read\n", sizeof("sys_enter_read\n"));

	bpf_map_update_elem(&FirstTime, &pid, &start_time, BPF_ANY);
	return 0;
}

SEC("kprobe/generic_file_read_iter")
int kprobe__generic_file_read_iter(void* ctx) {
	u64 exit_time = bpf_ktime_get_ns() / 1000;//us
	pid_t pid = bpf_get_current_pid_tgid();
	u64 start_time, delay;

	bpf_trace_printk("generic_file_read_iter\n", sizeof("generic_file_read_iter\n"));

	u64* val = bpf_map_lookup_elem(&FirstTime, &pid);
	if (val != 0) {
		return 0;
	}

	start_time = *val;
	delay = exit_time - start_time;
	bpf_map_delete_elem(&FirstTime, &pid);

	struct event e = {};

	e.pid = pid;
	e.duration1 = delay;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	bpf_perf_event_output(ctx, &events, 0, &e, sizeof(e));
	
	return 0;
}

// 进入到ext4文件系统，到在ext4 cache中读取相应数据
SEC("kprobe/generic_file_buffered_read")
int kprobe__generic_file_buffered_read(void* ctx) {
	u64 start_time = bpf_ktime_get_ns() / 1000;//ms
	pid_t pid = bpf_get_current_pid_tgid();

	bpf_trace_printk("generic_file_buffered_read\n", sizeof("generic_file_buffered_read\n"));

	bpf_map_update_elem(&SecondTime, &pid, &start_time, BPF_ANY);
	return 0;
}

SEC("kprobe/pagecache_get_page")
int kprobe__pagecache_get_page(void* ctx) {
	u64 exit_time = bpf_ktime_get_ns() / 1000;//ms
	pid_t pid = bpf_get_current_pid_tgid();
	u64 start_time, delay;

	bpf_trace_printk("pagecache_get_page\n", sizeof("pagecache_get_page\n"));

	u64* val = bpf_map_lookup_elem(&SecondTime, &pid);
	if (val != 0) {
		return 0;
	}

	start_time = *val;
	delay = exit_time - start_time;
	bpf_map_delete_elem(&SecondTime, &pid);

	struct event e = {};

	e.pid = pid;
	e.duration2 = delay;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	bpf_perf_event_output(ctx, &events, 0, &e, sizeof(e));

	return 0;
}

