#include "fs_watcher.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {	//记录时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} UnlinkSyscallEnterTime SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} unlink_rb SEC(".maps");//环形缓冲区；

static __always_inline int sys_enter_unlink()
{
    u64 start_time = bpf_ktime_get_ns()/1000;//ms
	pid_t pid = bpf_get_current_pid_tgid();//获取到当前进程的pid

	bpf_map_update_elem(&UnlinkSyscallEnterTime,&pid,&start_time,BPF_ANY);
	return 0;
}

static __always_inline int sys_exit_unlink()
{
	u64 exit_time = bpf_ktime_get_ns()/1000;//ms
	pid_t pid = bpf_get_current_pid_tgid();//获取到当前进程的pid
	u64 start_time, delay;

	u64 *val = bpf_map_lookup_elem(&UnlinkSyscallEnterTime, &pid);
	if(val !=0){
		start_time = *val;
		delay = exit_time - start_time;
		bpf_map_delete_elem(&UnlinkSyscallEnterTime, &pid);
	}else{ 
		return 0;
	}

	struct event *e;
	e = bpf_ringbuf_reserve(&unlink_rb, sizeof(*e), 0);
	if (!e)	return 0;

	e->pid = pid;
	e->duration_ns = delay;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);


	return 0; 
}

