#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "io_queue.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct io_queue);
} io_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/blk_mq_insert_request")
int BPF_KPROBE(blk_mq_insert_request, struct request *rq) {
    struct block_device *bi_bdev;
    u32 dev_num;
    unsigned int queue_depth;
    u64 ts;

    // 安全地读取 bio 和 bd_dev
    bi_bdev = BPF_CORE_READ(rq, bio, bi_bdev);
    dev_num = BPF_CORE_READ(bi_bdev, bd_dev);
    queue_depth = BPF_CORE_READ(rq, q, queue_depth);
    ts = bpf_ktime_get_ns()/1000;

    struct io_queue *val = bpf_map_lookup_elem(&io_queue, &dev_num);
    if (!val) {
        struct io_queue new_val = {0}; // 初始化
        new_val.ts = ts;
        new_val.tag = 1;
        new_val.dev_num = dev_num;
        new_val.max_queue_length = queue_depth;
        new_val.waiting_requests = 0;
        new_val.total_requests = 0;

        bpf_map_update_elem(&io_queue, &dev_num, &new_val, BPF_ANY);
        val = &new_val; // 使用新初始化的值
    } else {
        val->ts = ts;
        val->tag = 1;
        val->max_queue_length = queue_depth;
        val->waiting_requests++;
        val->total_requests++;
        bpf_map_update_elem(&io_queue, &dev_num, val, BPF_ANY);
    }

    struct io_queue *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->ts = val->ts;
    e->tag = val->tag;
    e->dev_num = val->dev_num;
    e->waiting_requests = val->waiting_requests;
    e->total_requests = val->total_requests;
    e->max_queue_length = val->max_queue_length;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/blk_mq_complete_request")
int BPF_KPROBE(blk_mq_complete_request, struct request *rq) {
    struct block_device *bi_bdev;
    u32 dev_num;
    u64 ts;

    bi_bdev = BPF_CORE_READ(rq, bio, bi_bdev);
    dev_num = BPF_CORE_READ(bi_bdev, bd_dev);
    ts = bpf_ktime_get_ns()/1000;
    
    struct io_queue *val = bpf_map_lookup_elem(&io_queue, &dev_num);
    if (val && val->waiting_requests > 0) {
        val->ts = ts;
        val->tag =2;
        val->waiting_requests--;
        //bpf_map_update_elem(&io_queue, &dev_num, &val, BPF_ANY);
    }

    struct io_queue *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    
    if (val) {
        e->ts = val->ts;
        e->tag = val->tag;
        e->dev_num = val->dev_num;
        e->waiting_requests = val->waiting_requests;
        e->total_requests = val->total_requests;
        e->max_queue_length = val->max_queue_length;
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

