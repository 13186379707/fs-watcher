// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Wenbo Zhang
//
// Based on biopattern(8) from BPF-Perf-Tools-Book by Brendan Gregg.
// 17-Jun-2020   Wenbo Zhang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bioinfo.h"
#include "bioinfo.skel.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

// Function to get device name from device number
static char *get_dev_name(__u32 dev_num) {
    static char name[32];
    unsigned int major = (dev_num >> 20) & 0xfff;
    unsigned int minor = dev_num & 0xfffff;
    char path[128];

    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/dev", major, minor);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(name, sizeof(name), "%u:%u", major, minor);
        return name;
    }

    int len = read(fd, name, sizeof(name) - 1);
    close(fd);
    if (len <= 0) {
        snprintf(name, sizeof(name), "%u:%u", major, minor);
        return name;
    }

    name[len] = '\0';
    char *newline = strchr(name, '\n');
    if (newline)
        *newline = '\0';

    if (strcmp(name, "11:0") == 0) {
        strncpy(name, "sr0", sizeof(name));
        name[sizeof(name) - 1] = '\0'; // 确保字符串以 null 结尾
    }
    if ((name[0] == '7') && (name[1] == ':') && (name[2] >= '0') && (name[2] <= '9') && (name[3] == '\0')) {
        char i = name[2];
        name[0] = 'l';
        name[1] = 'o';
        name[2] = 'o';
        name[3] = 'p';
        name[4] = i;
        name[5] = '\0';
    }
    if ((name[0] == '7') && (name[1] == ':') && (name[2] == '1') && (name[3] >= '0') && (name[3] <= '4') && (name[4] == '\0')) {
        char i = name[3];
        name[0] = 'l';
        name[1] = 'o';
        name[2] = 'o';
        name[3] = 'p';
        name[4] = i;
        name[5] = '\0';
    }
    if (strcmp(name, "8:0") == 0) {
        strncpy(name, "sda", sizeof(name));
        name[sizeof(name) - 1] = '\0';
    }
    if ((name[0] == '8') && (name[1] == ':') && (name[2] >= '1') && (name[2] <= '3') && (name[3] == '\0')) {
        char i = name[2];
        name[0] = 's';
        name[1] = 'd';
        name[2] = 'a';
        name[3] = i;
        name[4] = '\0';
    }
    
    return name;
}

static struct env {
	char *disk;
	time_t interval;
	bool timestamp;
	bool verbose;
	int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char argp_program_doc[] =
"Show block device I/O pattern.\n"
"\n"
"USAGE: biopattern [--help] [-T] [-d DISK] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    bioinfo              # show block I/O pattern\n"
"    bioinfo 1 10         # print 1 second summaries, 10 times\n"
"    bioinfo -T 1         # 1s summaries with timestamps\n"
"    bioinfo -d sdc       # trace sdc only\n";

static const struct argp_option opts[] = {
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "disk",  'd', "DISK",  0, "Trace this disk only" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		env.disk = arg;
		if (strlen(arg) + 1 > DISK_NAME_LEN) {
			fprintf(stderr, "invaild disk name: too long\n");
			argp_usage(state);
		}
		break;
	case 'T':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid internal\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_map(struct bpf_map *counters)
{
	__u32 total, lookup_key = -1, next_key;
	int err, fd = bpf_map__fd(counters);
	struct counter counter;
	struct tm *tm;
	char ts[32];
	time_t t;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &counter);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counters: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
		total = counter.sequential + counter.random;
		if (!total)
			continue;
		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-9s ", ts);
		}
        char *dev_name = get_dev_name(next_key);
		printf("%-7s %5ld %5ld %8d %10lld\n",
			dev_name,
			counter.random * 100L / total,
			counter.sequential * 100L / total, total,
			counter.bytes / 1024);
	}

	lookup_key = -1;
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "failed to cleanup counters: %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bioinfo_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = bioinfo_bpf__open_opts(&open_opts);
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = bioinfo_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bioinfo_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	printf("Tracing block device I/O requested seeks... Hit Ctrl-C to "
		"end.\n");
	if (env.timestamp)
		printf("%-9s ", "TIME");
	printf("%-7s %5s %5s %8s %10s\n", "DISK", "%RND", "%SEQ",
		"COUNT", "KBYTES");

	/* main: poll */
	while (1) {
		sleep(env.interval);

		err = print_map(obj->maps.counters);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	bioinfo_bpf__destroy(obj);

	return err != 0;
}