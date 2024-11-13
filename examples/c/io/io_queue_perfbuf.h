#ifndef __IO_QUEUE_PERFBUF_H
#define __IO_QUEUE_PERFBUF_H

struct io_queue {
    unsigned long long ts;
    unsigned int tag;
    unsigned long dev_num;
    unsigned long long waiting_requests;
    unsigned long long total_requests;
    unsigned long long max_queue_length;
};

#endif /* __IO_QUEUE_PERFBUF_H */