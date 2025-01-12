#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "fs_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static inline int handle_file_access(struct pt_regs *ctx, struct file *file, int op)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct event_t event = {};
    
    // Get process name and PID
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.pid = pid;
    event.op = op;
    
    // Get file path
    if (file) {
        struct path path;
        bpf_core_read(&path, sizeof(path), &file->f_path);

        if (!path.dentry) {
            return -1;
        }
        
        if (path.dentry) {
            struct dentry *dentry = path.dentry;
            const unsigned char *name;
            bpf_core_read(&name, sizeof(name), &dentry->d_name.name);
            if (name) {
                bpf_core_read_str(event.fname, sizeof(event.fname), (const char *)name);

                // Check if it's a file descriptor
                char first_char;
                bpf_probe_read(&first_char, 1, (const char *)name);
                event.is_fd = first_char >= '0' && first_char <= '9';
            }
        }
    }
    
    bpf_perf_event_output(ctx, &events, 0, &event, sizeof(event));
    return 0;
}

SEC("kprobe/vfs_open")
int kprobe__vfs_open(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM2(ctx);
    return handle_file_access(ctx, file, 1);
}

SEC("kprobe/vfs_read")
int kprobe__vfs_read(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    return handle_file_access(ctx, file, 2);
}

SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    return handle_file_access(ctx, file, 3);
}
