#include "write_response_time.bpf.h"

#include "unlink_response_time.bpf.h"

#include "rename_response_time.bpf.h"

#include "read_response_time.bpf.h"

#include "open_response_time.bpf.h"

#include "mount_response_time.bpf.h"

#include "ftruncate_response_time.bpf.h"

#include "chown_response_time.bpf.h"

#include "chmod_response_time.bpf.h"

#include "fs_monitor.bpf.h"

#include "event_monitor.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t fs_pid = -1;
const volatile char hostname[13] = "";
static struct common_event *e;

//fs_monitor
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

//event_monitor
SEC("tracepoint/raw_syscalls/sys_enter")//进入系统调用
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *args){
	return __sys_enter(args);
}

SEC("tracepoint/raw_syscalls/sys_exit")//退出系统调用
int tracepoint__raw_syscalls__sys_exit(struct trace_event_raw_sys_exit *args){
    return __sys_exit(args);
}

//chmod_event
SEC("tracepoint/syscalls/sys_enter_chmod")//进入sys_read
int tracepoint__syscalls__sys_enter_chmod(void *ctx){
	return sys_enter_chmod();
}

SEC("tracepoint/syscalls/sys_exit_chmod")//退出sys_read
int tracepoint__syscalls__sys_exit_chmod(void *ctx){
    return sys_exit_chmod();
}

//chown_event
SEC("tracepoint/syscalls/sys_enter_chown")//进入sys_read
int tracepoint__syscalls__sys_enter_chown(void *ctx){
	return sys_enter_chown();
}

SEC("tracepoint/syscalls/sys_exit_chown")//退出sys_read
int tracepoint__syscalls__sys_exit_chown(void *ctx){
	return sys_exit_chown();
}

//ftruncate_event
SEC("tracepoint/syscalls/sys_enter_ftruncate")//进入sys_read
int tracepoint__syscalls__sys_enter_ftruncate(void *ctx){
    return sys_enter_ftruncate();
}

SEC("tracepoint/syscalls/sys_exit_ftruncate")//退出sys_read
int tracepoint__syscalls__sys_exit_ftruncate(void *ctx){
    return sys_exit_ftruncate();
}

//mount_event
SEC("tracepoint/syscalls/sys_enter_mount")//进入sys_read
int tracepoint__syscalls__sys_enter_mount(void *ctx){
    return sys_enter_mount();
}

SEC("tracepoint/syscalls/sys_exit_mount")//退出sys_read
int tracepoint__syscalls__sys_exit_mount(void *ctx){
    return sys_exit_mount();
}

//open_event
SEC("tracepoint/syscalls/sys_enter_openat")//进入sys_read
int tracepoint__syscalls__sys_enter_open(void *ctx){
    return sys_enter_open();
}

SEC("tracepoint/syscalls/sys_exit_openat")//退出sys_read
int tracepoint__syscalls__sys_exit_open(void *ctx){
    return sys_exit_open();
}

//read_event
SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(void* ctx) {
    return sys_enter_read();
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(void* ctx) {
    return sys_exit_read();
}

//rename_event
SEC("tracepoint/syscalls/sys_enter_renameat2")//进入sys_read
int tracepoint__syscalls__sys_enter_rename(void *ctx){
    return sys_enter_rename();
}

SEC("tracepoint/syscalls/sys_exit_renameat2")//退出sys_read
int tracepoint__syscalls__sys_exit_rename(void *ctx){
    return sys_exit_rename();
}

//unlink_event
SEC("tracepoint/syscalls/sys_enter_unlinkat")//进入sys_read
int tracepoint__syscalls__sys_enter_unlink(void *ctx){
    return sys_enter_unlink();
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")//退出sys_read
int tracepoint__syscalls__sys_exit_unlink(void *ctx){
    return sys_exit_unlink();
}

//write_event
SEC("tracepoint/syscalls/sys_enter_write")//进入sys_read
int tracepoint__syscalls__sys_enter_write(void *ctx){
    return sys_enter_write();
}

SEC("tracepoint/syscalls/sys_exit_write")//退出sys_read
int tracepoint__syscalls__sys_exit_write(void *ctx){
    return sys_exit_write();
}
