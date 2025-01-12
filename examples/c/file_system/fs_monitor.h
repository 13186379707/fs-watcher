#ifndef FS_MONITOR_H
#define FS_MONITOR_H

#define DNAME_INLINE_LEN 32

// Event structure
struct event_t {
    char comm[16];
    int pid;
    char fname[256];
    int op;
    int is_fd;
};

#endif /* FS_MONITOR_H */