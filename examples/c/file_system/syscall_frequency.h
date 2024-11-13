#ifndef __SYSCALL_FREQUENCY_H
#define __SYSCALL_FREQUENCY_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct fs_t {
	unsigned long long count;
	unsigned long long ts;
    int pid;
	char comm[TASK_COMM_LEN];
};

#endif /* __SYSCALL_FREQUENCY_H */

