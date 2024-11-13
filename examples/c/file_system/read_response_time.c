#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "read_response_time.skel.h"	
#include "read_response_time.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void* ctx, void* data, unsigned long data_sz)
{
	const struct event* e = data;
	printf("opcode:read\t pid:%d\t duration_time:%llums\tcomm:%s\n", e->pid, e->duration_ns,e->comm);

	return 0;
}

/*
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
*/

int main(int argc, char** argv)
{
	struct ring_buffer* rb = NULL;
	struct read_response_time_bpf* skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	
	//libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);		
	signal(SIGTERM, sig_handler);

	skel = read_response_time_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = read_response_time_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = read_response_time_bpf__attach(skel);
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
		sleep(1);



	}

cleanup:
	ring_buffer__free(rb);
	read_response_time_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

