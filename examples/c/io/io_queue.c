#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>

#include "io_queue.skel.h"	
#include "io_queue.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void* ctx, void* data, unsigned long data_sz)
{
	const struct io_queue* e = data;
	unsigned int major = (e->dev_num >> 20) & 0xfff;
	unsigned int minor = e->dev_num &0xfff;
	printf("ts:%llu\ttag:%d\tdev numer:%d:%d\t\ttotal requests:%llu\t wait requests:%llu\tmax queue length:%llu\n", e->ts, e->tag, major, minor, e->total_requests, e->waiting_requests, e->max_queue_length);

	return 0;
}

int main(int argc, char** argv)
{
	struct io_queue_bpf* skel;
	int err;
    struct ring_buffer* rb = NULL;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	signal(SIGINT, sig_handler);		
	signal(SIGTERM, sig_handler);

	skel = io_queue_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = io_queue_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = io_queue_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);	
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);		
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	io_queue_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}