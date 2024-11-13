/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __FTRUNCATE_RESPONSE_TIME_H
#define __FTRUNCATE_RESPONSE_TIME_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN	 16
#endif
//#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
};

#endif /* __FTRUNCATE_RESPONSE_TIME_H */