#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include "event_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {	//记录时间戳
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} SyscallEnterTime SEC(".maps");

struct {	//记录系统调用号
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 10);
	__type(key, pid_t);
	__type(value, u64);
} Events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");//环形缓冲区；


SEC("tracepoint/raw_syscalls/sys_enter")//进入系统调用
int tracepoint__syscalls__sys_enter(struct trace_event_raw_sys_enter *args){
	u64 start_time = bpf_ktime_get_ns()/1000;//ms
	pid_t pid = bpf_get_current_pid_tgid();//获取到当前进程的pid
	u64 syscall_id = (u64)args->id;

	//bpf_printk("ID:%ld\n",syscall_id);
	bpf_map_update_elem(&Events,&pid,&syscall_id,BPF_ANY);
	bpf_map_update_elem(&SyscallEnterTime,&pid,&start_time,BPF_ANY);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")//退出系统调用
int tracepoint__syscalls__sys_exit(struct trace_event_raw_sys_exit *args){
	u64 exit_time = bpf_ktime_get_ns()/1000;//ms
	pid_t pid = bpf_get_current_pid_tgid() ;//获取到当前进程的pid
	u64 syscall_id;
	u64 start_time, delay;

	u64 *val = bpf_map_lookup_elem(&SyscallEnterTime, &pid);
	if(val !=0){
		start_time = *val;
		delay = exit_time - start_time;
		bpf_map_delete_elem(&SyscallEnterTime, &pid);
	}else{ 
		return 0;
	}

	u64 *val2 = bpf_map_lookup_elem(&Events, &pid);
	if(val2 !=0){
		syscall_id = *val2;
		bpf_map_delete_elem(&SyscallEnterTime, &pid);
	}else{ 
		return 0;
	}


	struct syscall_events *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;

	e->pid = pid;
	e->delay = delay;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->syscall_id = syscall_id;

	bpf_ringbuf_submit(e, 0);


	return 0;
}