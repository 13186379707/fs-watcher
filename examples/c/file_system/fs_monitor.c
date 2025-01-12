#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>

#include "fs_monitor.skel.h"	
#include "fs_monitor.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

// 修改后的 handle_event 函数签名
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event_t* e = data;
	switch (e->op)
	{
	case 1:
		printf("pid:%-10d opcode:opens  fliename:%-30s comm:%-15s is_fd:%d\n", e->pid, e->fname, e->comm, e->is_fd);
		break;

	case 2:
		printf("pid:%-10d opcode:reads  fliename:%-30s comm:%-15s is_fd:%d\n", e->pid, e->fname, e->comm, e->is_fd);
		break;
	
	case 3:
		printf("pid:%-10d opcode:writes fliename:%-30s comm:%-15s is_fd:%d\n", e->pid, e->fname, e->comm, e->is_fd);
		break;
	}
	

	//return 0;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char** argv)
{
	struct perf_buffer *pb = NULL;
	struct fs_monitor_bpf* skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	signal(SIGINT, sig_handler);		
	signal(SIGTERM, sig_handler);

	skel = fs_monitor_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = fs_monitor_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = fs_monitor_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                      handle_event, handle_lost_events, NULL, NULL);

    if (!pb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

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

cleanup:
	perf_buffer__free(pb);
	fs_monitor_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}