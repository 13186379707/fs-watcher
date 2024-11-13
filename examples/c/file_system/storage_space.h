#ifndef __STORAGE_SPACE_H
#define __STORAGE_SPACE_H

#include "magic.h"

struct disk_usage {
	unsigned long long type;
    	unsigned long long size;
    	unsigned long long used;
    	unsigned long long avail;
    	unsigned long long i_size;
    	unsigned long long i_used;
    	unsigned long long i_avail;
};

#endif /* __STORAGE_SPACE_H */
