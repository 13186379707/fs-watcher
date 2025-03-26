#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "io_fs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 每个CPU独立计数
// 每个entry含义：0: read_count, 1: read_size, 2: write_count, 3: write_size, 4:meta_reads_count, 5:meta_reads_size 6:meta_writes_count, 7:meta_writes_count, 8:dirty_page
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 9);  
    __type(key, u32);
    __type(value, u64);
} fs_ops SEC(".maps");

// 环形缓冲区（用于传递统计结果）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 文件数据读的次数
SEC("kprobe/ext4_file_read_iter")
int kprobe__ext4_file_read_iter(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&fs_ops, &key);
    if (count) (*count)++;

    return 0;
}

// 文件数据读的数据量
SEC("kretprobe/ext4_file_read_iter")
int kretprobe__ext4_file_read_iter(struct pt_regs *ctx) {
    u32 key = 1;
    ssize_t size = (ssize_t)PT_REGS_RC(ctx);
    u64 *count = bpf_map_lookup_elem(&fs_ops, &key);
    if (count) (*count) += size;

    return 0;
}

// 文件数据写的次数
SEC("kprobe/ext4_file_write_iter")
int kprobe__ext4_file_write_iter(struct pt_regs *ctx) {
    u32 key = 2;
    u64 *count = bpf_map_lookup_elem(&fs_ops, &key);
    if (count) (*count)++;

    return 0;
}

// 文件数据写的数据量
SEC("kretprobe/ext4_file_write_iter")
int kretprobe__ext4_file_write_iter(struct pt_regs *ctx) {
    u32 key = 3;
    ssize_t size = (ssize_t)PT_REGS_RC(ctx);
    u64 *count = bpf_map_lookup_elem(&fs_ops, &key);
    if (count) (*count) += size;

    return 0;
}

// 元数据读（getattr等）
SEC("kprobe/ext4_file_getattr")
int kprobe__ext4_file_getattr(struct pt_regs *ctx) {
    u32 key = 4;
    u64 *count = bpf_map_lookup_elem(&fs_ops, &key);
    if (count) (*count)++;

    key = 5;
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
    struct ext4_sb_info *sbi = (struct ext4_sb_info *)BPF_CORE_READ(inode, i_sb, s_fs_info);
    unsigned long long inode_size = (unsigned long long)BPF_CORE_READ(sbi, s_inode_size);
    u64 *count_meta = bpf_map_lookup_elem(&fs_ops, &key);
    if (count_meta) (*count_meta) += inode_size;

    return 0;
}

// 元数据写（setattr等）
SEC("kprobe/ext4_setattr")
int kprobe__ext4_setattr(struct pt_regs *ctx) {
    u32 key = 6;
    u64 *count = bpf_map_lookup_elem(&fs_ops, &key);
    if (count) (*count)++;

    key = 7;
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM1(ctx);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    struct ext4_sb_info *sbi = (struct ext4_sb_info *)BPF_CORE_READ(inode, i_sb, s_fs_info);
    unsigned long long inode_size = (unsigned long long)BPF_CORE_READ(sbi, s_inode_size);
    u64 *count_meta = bpf_map_lookup_elem(&fs_ops, &key);
    if (count_meta) (*count_meta) += inode_size;

    return 0;
}

// 脏页数（可通过标记脏页的行为函数__set_page_dirty的调用次数进行计数，__set_page_dirty函数一次一般只标记一页为脏）
/* 这里的脏页数只代表标记为脏的页有多少，但实际每页的大小是不固定的，因为会存在大页（Huge Pages）的情况 */
SEC("kprobe/__set_page_dirty")
int kprobe____set_page_dirty(struct pt_regs *ctx) {
    u32 key = 8;
    u64 *cnt = bpf_map_lookup_elem(&fs_ops, &key);
    if (cnt) (*cnt)++;

    return 0;
}

// 每秒触发统计提交（通过用户态轮询触发）
SEC("kprobe/__x64_sys_nanosleep")  // 任意高频系统调用（如nanosleep）
int kprobe__trigger_stats(struct pt_regs *ctx) {
    u32 key;
    u64 total_reads = 0, total_writes = 0, 
    metadata_reads = 0, metadata_writes = 0, 
    read_size = 0, write_size = 0,
    metadata_reads_size = 0, metadata_writes_size = 0,
    dirty_page;

    // 汇总所有CPU的读计数
    key = 0;
    u64 *readc = bpf_map_lookup_elem(&fs_ops, &key);
    if (readc) total_reads = *readc;

    key = 1;
    u64 *reads = bpf_map_lookup_elem(&fs_ops, &key);
    if (reads) read_size = *reads;

    // 汇总所有CPU的写计数
    key = 2;
    u64 *writec = bpf_map_lookup_elem(&fs_ops, &key);
    if (writec) total_writes = *writec;

    key = 3;
    u64 *writes = bpf_map_lookup_elem(&fs_ops, &key);
    if (writes) write_size = *writes;

    // 汇总所有CPU的元数据读计数
    key = 4;
    u64 *mreads = bpf_map_lookup_elem(&fs_ops, &key);
    if (mreads) metadata_reads = *mreads;

    key = 5;
    u64 *mread_size = bpf_map_lookup_elem(&fs_ops, &key);
    if (mread_size) metadata_reads_size = *mread_size;

    // 汇总所有CPU的元数据写计数
    key = 6;
    u64 *mwrites = bpf_map_lookup_elem(&fs_ops, &key);
    if (mwrites) metadata_writes = *mwrites;

    key = 7;
    u64 *mwrite_size = bpf_map_lookup_elem(&fs_ops, &key);
    if (mwrite_size) metadata_writes_size = *mwrite_size;

    // 汇总所有CPU的脏页计数
    key = 8;
    u64 *dirtyc = bpf_map_lookup_elem(&fs_ops, &key);
    if (dirtyc) dirty_page = *dirtyc;

    // 提交到环形缓冲区
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->read_count = total_reads;
    e->write_count = total_writes;
    e->read_psize = read_size;
    e->write_psize = write_size;
    e->metadata_reads = metadata_reads;
    e->metadata_writes = metadata_writes;
    e->metadata_reads_size = metadata_reads_size;
    e->metadata_writes_size = metadata_writes_size;
    e->dirty_page = dirty_page;

    bpf_ringbuf_submit(e, 0);

    // 重置计数器（可选）
    u64 zero = 0;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 脏页计数器
    key = 7;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 元数据写数据量计数器
    key = 6;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 元数据写计数器
    key = 5;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 元数据读计数器
    key = 4;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 元数据读计数器
    key = 3;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 写数据量计数器
    key = 2;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 写计数器
    key = 1;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 读数据量计数器
    key = 0;
    bpf_map_update_elem(&fs_ops, &key, &zero, BPF_ANY);  // 读计数器

    return 0;
}