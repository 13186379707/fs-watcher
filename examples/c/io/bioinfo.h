// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __BIOINFO_H
#define __BIOINFO_H

#define DISK_NAME_LEN	32

struct counter {
	__u64 last_sector;
	__u64 bytes;
	__u32 sequential;
	__u32 random;
};

#endif /* __BIOIBFO_H */