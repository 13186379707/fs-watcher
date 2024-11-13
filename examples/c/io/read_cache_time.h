/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __READ_CACHE_TIME_H
#define __READ_CACHE_TIME_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN	 16
#endif
//#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	unsigned long long duration1;
	unsigned long long duration2;
	unsigned long long duration3;
	char comm[TASK_COMM_LEN];
};

#endif /* __READ_CACHE_TIME_H */
