#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>

#include "system_io.skel.h"	
#include "system_io.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char** argv)
{
	struct system_io_bpf* skel;
	int err;
    struct bpf_map *map_fd;
    int index = 0;
    struct system_io value;

	//libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	signal(SIGINT, sig_handler);		
	signal(SIGTERM, sig_handler);

	skel = system_io_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = system_io_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = system_io_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    map_fd = bpf_object__find_map_by_name(skel->obj, "system_io");
    if (!map_fd) {
        fprintf(stderr, "Failed to find system_io map\n");
        goto cleanup;
    }

    while (!exiting) {
		memset(&value, 0, sizeof(value));

        if (bpf_map__lookup_elem(map_fd, &index, sizeof(index), &value, sizeof(value), BPF_ANY) == 0) {
            printf("IOPS(次/s):%8llu\t\tThroughput(B/s):%10llu\n", value.iops_count, value.throughput_count);

            value.iops_count = 0;
            value.throughput_count = 0;

            bpf_map__update_elem(map_fd, &index, sizeof(index), &value, sizeof(value), BPF_ANY);
        }

        sleep(1);
    }

cleanup:
	system_io_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}