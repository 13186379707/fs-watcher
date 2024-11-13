#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "io_queue_perfbuf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct io_queue);
} io_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static inline void update_io_queue(void *ctx, u32 dev_num, u64 ts, unsigned int queue_depth, int is_insert) {
    struct io_queue *val = bpf_map_lookup_elem(&io_queue, &dev_num);
    if (!val) {
        struct io_queue new_val = {}; // 初始化
        new_val.ts = ts;
        new_val.tag = is_insert ? 1 : 2;
        new_val.dev_num = dev_num;
        new_val.max_queue_length = queue_depth; // 可以在其他地方设置
        new_val.waiting_requests = 1;
        new_val.total_requests = 0;

        bpf_map_update_elem(&io_queue, &dev_num, &new_val, BPF_ANY);
        val = &new_val; // 使用新初始化的值
    } else {
        val->ts = ts;
        val->tag = is_insert ? 1 : 2;
        if (is_insert) {
            val->waiting_requests++;
            val->total_requests++;
        } else if (val->waiting_requests > 0) {
            val->waiting_requests--;
        }
        bpf_map_update_elem(&io_queue, &dev_num, val, BPF_ANY);
    }

    bpf_perf_event_output(ctx, &events, 0, val, sizeof(*val));
}

SEC("kprobe/blk_mq_insert_request")
int BPF_KPROBE(blk_mq_insert_request, struct request *rq) {
    struct block_device *bi_bdev;
    u32 dev_num;
    unsigned int queue_depth;
    u64 ts;

    bi_bdev = BPF_CORE_READ(rq, bio, bi_bdev);
    dev_num = BPF_CORE_READ(bi_bdev, bd_dev);
    queue_depth = BPF_CORE_READ(rq, q, queue_depth);
    ts = bpf_ktime_get_ns()/1000;

    update_io_queue(ctx, dev_num, ts,queue_depth, 1); // 插入请求时调用
    return 0;
}

SEC("kprobe/blk_mq_complete_request")
int BPF_KPROBE(blk_mq_complete_request, struct request *rq) {
    struct block_device *bi_bdev;
    u32 dev_num;
    unsigned int queue_depth;
    u64 ts;

    bi_bdev = BPF_CORE_READ(rq, bio, bi_bdev);
    dev_num = BPF_CORE_READ(bi_bdev, bd_dev);
    queue_depth = BPF_CORE_READ(rq, q, queue_depth);
    ts = bpf_ktime_get_ns()/1000;

    update_io_queue(ctx, dev_num, ts, queue_depth, 0); // 完成请求时调用
    return 0;
}
