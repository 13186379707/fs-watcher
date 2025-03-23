#ifndef __IO_VFS_CACHE_H
#define __IO_VFS_CACHE_H

// 定义统计信息结构体
struct stats {
    signed long long total;      // 总访问次数
    signed long long file_hits;  // 文件缓存命中次数
    signed long long anon_hits;  // 匿名页缓存命中次数
    signed long long misses;     // 缓存未命中次数
    unsigned long long mbd;      // Mark buffer dirty 事件
    unsigned int pid;            // 进程 ID
};

#endif /* __IO_VFS_CACHE_H */