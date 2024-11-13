#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include "write_response_time.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {	//记录时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} SyscallEnterTime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");//环形缓冲区；


SEC("tracepoint/syscalls/sys_enter_write")//进入sys_read
int tracepoint__syscalls__sys_enter_write(void *ctx){
	u64 start_time = bpf_ktime_get_ns()/1000;//ms
	pid_t pid = bpf_get_current_pid_tgid();//获取到当前进程的pid

	bpf_map_update_elem(&SyscallEnterTime,&pid,&start_time,BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")//退出sys_read
int tracepoint__syscalls__sys_exit_write(void *ctx){
	u64 exit_time = bpf_ktime_get_ns()/1000;//ms
	pid_t pid = bpf_get_current_pid_tgid() ;//获取到当前进程的pid
	u64 start_time, delay;

	u64 *val = bpf_map_lookup_elem(&SyscallEnterTime, &pid);
	if(val !=0){
		start_time = *val;
		delay = exit_time - start_time;
		bpf_map_delete_elem(&SyscallEnterTime, &pid);
	}else{ 
		return 0;
	}

	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;

	e->pid = pid;
	e->duration_ns = delay;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);


	return 0;
}