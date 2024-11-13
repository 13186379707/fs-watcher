#ifndef __EVENT_MONITOR_H
#define __EVENT_MONITOR_H

#include "x86_64_syscall.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN	 16
#endif

struct syscall_events {
	int pid;
	unsigned long long delay;
	char comm[TASK_COMM_LEN];
    unsigned long long syscall_id;
};

#endif /* __EVENT_MONITOR_H */
