#ifndef IO_WATCHER_H
#define IO_WATCHER_H

//write_disk_time
struct event {
	int pid;
	unsigned long long duration1;
	unsigned long long duration2;
	unsigned long long duration3;
	char comm[16];
};

#endif /* IO_WATCHER_H */