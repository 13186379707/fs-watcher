#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "syscall_frequency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} fdtmp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__syscalls__sys_enter(struct trace_event_raw_sys_enter *args)
{
    struct fs_t fs = {};
    u64 tgid;
    pid_t pid;
    
    tgid = bpf_get_current_pid_tgid();
    pid = tgid >> 32;
    unsigned long long ts = bpf_ktime_get_ns();
    fs.ts = ts;
    u64 *val = bpf_map_lookup_elem(&fdtmp, &tgid);
    if(val != NULL){
        fs.count = (*val) + 1;
    } else {
        fs.count = 1; // Initialize count to 1 if not found in fdtmp
    }
    bpf_map_update_elem(&fdtmp, &tgid, &fs.count, BPF_ANY);
    fs.pid = pid;
    bpf_get_current_comm(fs.comm, sizeof(fs.comm));
    
    struct fs_t* e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)    return 0;
    
    e->count = fs.count;
    e->ts = fs.ts;
    e->pid = fs.pid;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}
