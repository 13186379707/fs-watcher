#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		
#include <bpf/bpf_tracing.h>
#include "storage_space.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义哈希映射
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct disk_usage);
} disk_usage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/vfs_statfs")
int kprobe_vfs_statfs(struct pt_regs *ctx)
{
	struct kstatfs statfs;
	bpf_probe_read(&statfs, sizeof(struct kstatfs), (void *)PT_REGS_PARM2(ctx));
    	struct disk_usage du = {};

    	du.type = statfs.f_type;
    	du.size = (u64)statfs.f_blocks * (u64)statfs.f_bsize;
    	du.avail = (u64)statfs.f_bavail * (u64)statfs.f_bsize;
    	du.used = du.size - du.avail;
    	du.i_size = (u64)statfs.f_files;
    	du.i_avail = (u64)statfs.f_ffree;
    	du.i_used = du.i_size - du.i_avail;

    	int err = bpf_map_update_elem(&disk_usage, &statfs.f_type, &du, BPF_ANY);
    	if (err) { // 更新错误
        	bpf_printk("disk_usage update err.\n");
        	return 0;
		}
    
    //从环形缓冲区（ring buffer）中分配一块内存来存储一个名为 struct disk_usage类型的数据，并将该内存块的指针赋值给指针变量 e
	struct disk_usage *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;	
	
	//给变量e赋值
	e->type = du.type;
	e->size = du.size;
	e->avail = du.avail;
	e->used = du.used;
	e->i_size = du.i_size;
	e->i_avail = du.i_avail;
	e->i_used = du.i_used;
	
	// 成功地将其提交到用户空间进行后期处理
	bpf_ringbuf_submit(e, 0);

    
    return 0;
}

char _license[] SEC("license") = "GPL";

