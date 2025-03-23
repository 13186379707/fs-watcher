#ifndef __IO_VFS_H
#define __IO_VFS_H

#ifndef FILENAME_MAX
#define FILENAME_MAX 256
#endif

#ifndef DNAME_INLINE_LEN
#define DNAME_INLINE_LEN 32
#endif

// Event structure
struct event_t {
    char comm[16];
    int pid;
    char fname[256];
    int op;
    int is_fd;
};

#endif /* __IO_VFS_H */