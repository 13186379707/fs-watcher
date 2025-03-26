#ifndef __IO_FS_H
#define __IO_FS_H

struct event {
    // 文件数据操作
    unsigned long long read_count;  // 读取操作的次数
    unsigned long long write_count; // 写入操作的次数
    /* 在ext4文件系统中，size（文件逻辑大小）和 blocks（占用的磁盘块数）并不总是保持一致，例如稀疏矩阵存储、文件压缩或加密等场景 */
    unsigned long long read_psize;  // 读取操作的实际空间大小
    unsigned long long write_psize; // 写入操作的实际空间大小
    // 元数据操作
    unsigned long long metadata_reads;  // getattr/listxattr/get_acl等
    unsigned long long metadata_writes; // setattr/set_acl等
};

#endif /* __IO_FS_H */