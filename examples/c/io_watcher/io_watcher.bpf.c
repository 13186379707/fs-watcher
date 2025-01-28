#include "common.bpf.h"

#include "io_queue.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t fs_pid = -1;
const volatile char hostname[13] = "";
static struct common_event *e;

//io_queue
SEC("kprobe/__blk_mq_insert_request")
int kprobe__blk_mq_insert_request(struct pt_regs *ctx) {    //利用bpf_trace_printk进行代码调试，看看问题出在哪里   
    struct request *rq = (struct request *)PT_REGS_PARM2(ctx);
    return blk_mq_insert_request(rq);
}

SEC("kprobe/blk_mq_complete_request")
int kprobe__blk_mq_complete_request(struct pt_regs *ctx) {
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    return blk_mq_complete_request(rq);
}
