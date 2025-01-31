#include "common.bpf.h"

#include "write_disk_time.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t fs_pid = -1;
const volatile char hostname[13] = "";
static struct common_event *e;

//write_disk_time
    //启用flush线程，开始执行writeback任务
SEC("kprobe/wb_workfn")
int kprobe__wb_start_writeback(void *ctx){
    return wb_start_writeback();
}

SEC("kprobe/do_writepages")
int kprobe__ext4_do_writepages(void *ctx){
    return ext4_do_writepages(ctx);
}

    //I/O调度层
SEC("kprobe/ext4_io_submit")
int kprobe__ext4_io_submit(void *ctx){
    return ext4_io_submit();
}

SEC("kprobe/blk_mq_dispatch_rq_list")
int kprobe__blk_mq_dispatch_rq_list(void *ctx){
    return blk_mq_dispatch_rq_list(ctx);
}

    //设备驱动层
SEC("kprobe/scsi_queue_rq")
int kprobe__submit_bio(void *ctx){
    return submit_bio();
}

SEC("kprobe/scsi_finish_command")
int kprobe__scsi_finish_command(void *ctx){
    return scsi_finish_command(ctx);
}
