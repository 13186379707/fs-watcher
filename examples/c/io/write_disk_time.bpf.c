#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include "write_disk_time.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {	//记录通用设备层时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} FirstTime SEC(".maps");

struct {	//记录I/O调度层时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} SecondTime SEC(".maps");

struct {	//记录设备驱动层时间戳
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, pid_t);
	__type(value, u64);
} ThirdTime SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");	//perf缓冲区

// 启用flush线程，开始执行writeback任务
SEC("kprobe/wb_workfn")
int kprobe__wb_start_writeback(void *ctx){
	u64 start_time = bpf_ktime_get_ns()/1000;//us
	pid_t pid = bpf_get_current_pid_tgid();//获取到当前进程的pid

	//bpf_trace_printk("wb_workfn\n", sizeof("wb_workfn\n"));

	bpf_map_update_elem(&FirstTime,&pid,&start_time,BPF_ANY);
	return 0;
}

SEC("kprobe/do_writepages")
int kprobe__ext4_do_writepages(void *ctx){
	u64 exit_time = bpf_ktime_get_ns()/1000;//us
	pid_t pid = bpf_get_current_pid_tgid() ;//获取到当前进程的pid
	u64 start_time, delay;

	//bpf_trace_printk("do_writepages\n", sizeof("do_writepages\n"));

	u64 *val = bpf_map_lookup_elem(&FirstTime, &pid);
	if(!val){
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

// I/O调度层
SEC("kprobe/ext4_io_submit")
int kprobe__ext4_io_submit(void *ctx){
	u64 start_time = bpf_ktime_get_ns()/1000;//us
	pid_t pid = bpf_get_current_pid_tgid();//获取到当前进程的pid

	//bpf_trace_printk("ext4_io_submit\n", sizeof("ext4_io_submit\n"));

	bpf_map_update_elem(&SecondTime,&pid,&start_time,BPF_ANY);
	return 0;
}

SEC("kprobe/blk_mq_dispatch_rq_list")
int kprobe__blk_mq_dispatch_rq_list(void *ctx){
	u64 exit_time = bpf_ktime_get_ns()/1000;//us
	pid_t pid = bpf_get_current_pid_tgid() ;//获取到当前进程的pid
	u64 start_time, delay;

	//bpf_trace_printk("blk_mq_dispatch_rq_list\n", sizeof("blk_mq_dispatch_rq_list\n"));

	u64 *val = bpf_map_lookup_elem(&SecondTime, &pid);
	if(!val){
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

// 设备驱动层
SEC("kprobe/scsi_queue_rq")
int kprobe__submit_bio(void *ctx){
	u64 start_time = bpf_ktime_get_ns()/1000;//us
	pid_t pid = bpf_get_current_pid_tgid();//获取到当前进程的pid

	//bpf_trace_printk("scsi_queue_rq\n", sizeof("scsi_queue_rq\n"));

	bpf_map_update_elem(&ThirdTime,&pid,&start_time,BPF_ANY);
	return 0;
}

SEC("kprobe/scsi_finish_command")
int kprobe__scsi_finish_command(void *ctx){
	u64 exit_time = bpf_ktime_get_ns()/1000;//us
	pid_t pid = bpf_get_current_pid_tgid() ;//获取到当前进程的pid
	u64 start_time, delay;

	//bpf_trace_printk("scsi_finish_command\n", sizeof("scsi_finish_command\n"));

	u64 *val = bpf_map_lookup_elem(&ThirdTime, &pid);
	if(!val){
		return 0;
	}

	start_time = *val;
	delay = exit_time - start_time;
	bpf_map_delete_elem(&ThirdTime, &pid);

	struct event e = {};

	e.pid = pid;
	e.duration3 = delay;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	bpf_perf_event_output(ctx, &events, 0, &e, sizeof(e));

	return 0;
}