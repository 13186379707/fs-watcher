#ifndef IO_WATCHER_H
#define IO_WATCHER_H

//io_queue
struct dev_num {
    int major;
    int minor;
};

// dev_num比较函数
int compare_dev_num(struct dev_num a, struct dev_num b) 
{
    return (a.major == b.major) && (a.minor == b.minor);
}

struct io_queue {
    unsigned long long ts;
    unsigned int tag;
    struct dev_num dev_num;
    unsigned long long waiting_requests;
    unsigned long long total_requests;
    unsigned long long max_queue_length;
};

#endif /* IO_WATCHER_H */