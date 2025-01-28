#include "io_watcher.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dev_num);
    __type(value, struct io_queue);
} io_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} io_queue_rb SEC(".maps");

static __always_inline int blk_mq_insert_request(struct request *rq)
{
    struct request_queue *q;
    struct gendisk *disk;
    struct dev_num dev_num;
    unsigned int queue_depth;
    u64 ts;

    q = BPF_CORE_READ(rq, q);
    if (!q) {
        return 0;
    }

    disk = BPF_CORE_READ(q, disk);
    if (!disk) {
        return 0;
    }

    dev_num.major = BPF_CORE_READ(disk, major);
    dev_num.minor = BPF_CORE_READ(disk, first_minor);
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

    char fmt[] = "Failed to reserve space in ring buffer in blk_mq_insert_request\n";
    struct io_queue *e = bpf_ringbuf_reserve(&io_queue_rb, sizeof(*e), 0);
    if (!e) {
        bpf_trace_printk(fmt, sizeof(fmt));
        return 0;
    }

    e->ts = val->ts;
    e->tag = val->tag;
    e->dev_num = val->dev_num;
    e->waiting_requests = val->waiting_requests;
    e->total_requests = val->total_requests;
    e->max_queue_length = val->max_queue_length;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

static __always_inline int blk_mq_complete_request(struct request *rq)
{
    struct request_queue *q;
    struct gendisk *disk;
    struct dev_num dev_num;
    u64 ts;

    q = BPF_CORE_READ(rq, q);
    if (!q) {
        return 0;
    }

    disk = BPF_CORE_READ(q, disk);
    if (!disk) {
        return 0;
    }

    dev_num.major = BPF_CORE_READ(disk, major);
    dev_num.minor = BPF_CORE_READ(disk, first_minor);
    ts = bpf_ktime_get_ns()/1000;
    
    struct io_queue *val = bpf_map_lookup_elem(&io_queue, &dev_num);
    if (val && val->waiting_requests > 0) {
        val->ts = ts;
        val->tag = 2;
        val->waiting_requests--;
        bpf_map_update_elem(&io_queue, &dev_num, val, BPF_ANY);
    }

    char fmt[] = "Failed to reserve space in ring buffer in blk_mq_complete_request\n";
    struct io_queue *e = bpf_ringbuf_reserve(&io_queue_rb, sizeof(*e), 0);
    if (!e) {
        bpf_trace_printk(fmt, sizeof(fmt));
        return 0;
    }
    
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