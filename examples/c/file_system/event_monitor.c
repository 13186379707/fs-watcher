#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "event_monitor.skel.h"	//包含了 BPF 字节码和相关的管理函数
#include "event_monitor.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct syscall_events *e = data;
	switch (e->syscall_id) {
		case sys_epoll_create1 :
		case sys_timerfd_create :
		case sys_timer_create :
		case sys_memfd_create :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:create\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_openat :
		case sys_mq_open :
		case sys_perf_event_open :
		case sys_open_by_handle_at :
		case sys_open_tree :
		case sys_fsopen :
		case sys_pidfd_open :
		case sys_openat2 :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:open\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_read :
		case sys_readv :
		case sys_pread64 :
		case sys_preadv :
		case sys_readlinkat :
		case sys_readahead :
		case sys_process_vm_readv :
		case sys_preadv2 :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:read\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_write :
		case sys_writev :
		case sys_pwrite64 :
		case sys_pwritev :
		case sys_process_vm_writev :
		case sys_pwritev2 :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:write\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_unlinkat :
		case sys_mq_unlink :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:unlink\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_renameat2 :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:rename\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_ftruncate64 :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:ftruncate\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_fchmod :
		case sys_fchmodat :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:chmod\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_fchownat :
		case sys_fchown :
			printf("pid:%d\tdelay:%llu\tcomm:%s\tsyscall_id:%llu\tevent:chown\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		default:
			//printf("pid:%d delay:%llu comm:%s syscall_id:%llu syscall:other\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
        }
	
	return 0;
}

/*
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
*/

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct event_monitor_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* 设置libbpf错误和调试信息回调 */
	//libbpf_set_print(libbpf_print_fn);

	/* 更干净地处理Ctrl-C
	   SIGINT：由Interrupt Key产生，通常是CTRL+C或者DELETE。发送给所有ForeGround Group的进程
       SIGTERM：请求中止进程，kill命令发送
	*/
	signal(SIGINT, sig_handler);		//signal设置某一信号的对应动作
	signal(SIGTERM, sig_handler);

	/* 打开BPF应用程序 */
	skel = event_monitor_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	/* 加载并验证BPF程序 */
	err = event_monitor_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	/* 附加跟踪点处理程序 */
	err = event_monitor_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	/* 设置环形缓冲区轮询 */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	/* 处理事件 */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);		//ring_buffer__poll(),轮询打开ringbuf缓冲区。如果有事件，handle_event函数会执行
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
		
		
		
	}
	
/* 卸载BPF程序 */
cleanup:
	ring_buffer__free(rb);
	event_monitor_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}

