#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "syscall_frequency.skel.h"	
#include "syscall_frequency.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void* ctx, void* data, unsigned long data_sz)
{
	const struct fs_t* e = data;
	printf("pid:%d\t time:%llu\t count:%llu\t comm:%s\n", e->pid,  e->ts, e->count, e->comm);

	return 0;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char** argv)
{
	struct ring_buffer* rb = NULL;
	struct syscall_frequency_bpf* skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);		
	signal(SIGTERM, sig_handler);

	skel = syscall_frequency_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = syscall_frequency_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = syscall_frequency_bpf__attach(skel);
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
		err = ring_buffer__poll(rb, 1000 /* timeout, ms */);		
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}

		//exiting = true;			

	}

cleanup:
	ring_buffer__free(rb);
	syscall_frequency_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

