#ifndef FS_WATCHER_H
#define FS_WATCHER_H

void print_logo();

//fs_watcher
#define DNAME_INLINE_LEN 32

struct event_t {
    char comm[16];
    int pid;
    char fname[256];
    int op;
    int is_fd;
};

//event_monitor
#include "x86_64_syscall.h"

struct syscall_events {
	int pid;
	unsigned long long delay;
	char comm[16];
    unsigned long long syscall_id;
};

//chmod_event/chown_event
struct event {
	int pid;
	unsigned long long duration_ns;
	char comm[16];
};


#endif /* FS_WATCHER_H */