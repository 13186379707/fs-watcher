#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "read_cache_time.skel.h"	
#include "read_cache_time.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event *e = data;
	printf("opcode:read data from user to cache    pid:%d    duration1(us)_time:%-10llu duration2(us)_time:%-10llu comm:%s\n", e->pid, e->duration1, e->duration2, e->comm);
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

int main(int argc, char** argv)
{
	struct perf_buffer *pb = NULL;
	struct read_cache_time_bpf* skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	
	//libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);		
	signal(SIGTERM, sig_handler);

	skel = read_cache_time_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = read_cache_time_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = read_cache_time_bpf__attach(skel);
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
	read_cache_time_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

