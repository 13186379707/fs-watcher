#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "write_disk_time.skel.h"	//包含了 BPF 字节码和相关的管理函数
#include "write_disk_time.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event *e = data;
	printf("opcode:write data from cache to disk    pid:%-10d duration1_time(us):%-10llu duration2_time(us):%-10llu duration3_time(us):%-10llu comm:%s\n", e->pid, e->duration1,e->duration2, e->duration3, e->comm);
}

/*
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
*/

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct write_disk_time_bpf *skel;
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
	skel = write_disk_time_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	/* 加载并验证BPF程序 */
	err = write_disk_time_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	/* 附加跟踪点处理程序 */
	err = write_disk_time_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	/* 设置环形缓冲区轮询 */
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                      handle_event, handle_lost_events, NULL, NULL);
	if (!pb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	/* 处理事件 */
	while (!exiting)
	{
		err = perf_buffer__poll(pb, -1);		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}
	
/* 卸载BPF程序 */
cleanup:
	perf_buffer__free(pb);
	write_disk_time_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}

