#ifndef __X86_64_SYSCALL_H
#define __X86_64_SYSCALL_H

//orgin:/include/uapi/asm-generic/unistd.h
#define sys_io_setup 0
#define sys_io_destroy 1
#define sys_io_submit 2
#define sys_io_cancel 3
#define sys_io_getevents_time32 4

/* fs/xattr.c */
#define sys_setxattr 5
#define sys_lsetxattr 6
#define sys_fsetxattr 7
#define sys_getxattr 8
#define sys_lgetxattr 9
#define sys_fgetxattr 10
#define sys_listxattr 11
#define sys_llistxattr 12
#define sys_flistxattr13
#define sys_removexattr 14
#define sys_lremovexattr 15
#define sys_fremovexattr 16

/* fs/dcache.c */
#define sys_getcwd 17

/* fs/cookies.c */
#define sys_lookup_dcookie 18

/* fs/eventfd.c */
#define sys_eventfd2 19

/* fs/eventpoll.c */
#define sys_epoll_create1 20
#define sys_epoll_ctl 21
#define sys_epoll_pwait 22

/* fs/fcntl.c */
#define sys_dup 23
#define sys_dup3 24
#define sys_fcntl64 25

/* fs/inotify_user.c */
#define sys_inotify_init1 26
#define sys_inotify_add_watch 27
#define sys_inotify_rm_watch 28

/* fs/ioctl.c */
#define sys_ioctl 29

/* fs/ioprio.c */
#define sys_ioprio_set 30
#define sys_ioprio_get 31

/* fs/locks.c */
#define sys_flock 32

/* fs/namei.c */
#define sys_mknodat 33
#define sys_mkdirat 34
#define sys_unlinkat 35
#define sys_symlinkat 36
#define sys_linkat 37
#ifdef __ARCH_WANT_RENAMEAT
/* renameat is superseded with flags by renameat2 */
#define sys_renameat 38
#endif /* __ARCH_WANT_RENAMEAT */

/* fs/namespace.c */
#define sys_umount 39
#define sys_mount 40
#define sys_pivot_root 41

/* fs/nfsctl.c */
#define sys_ni_syscall 42

/* fs/open.c */
#define sys_statfs64 43
#define sys_fstatfs64 44
#define sys_truncate64 45
#define sys_ftruncate64 46

#define sys_fallocate 47
#define sys_faccessat 48
#define sys_chdir 49
#define sys_fchdir 50
#define sys_chroot 51
#define sys_fchmod 52
#define sys_fchmodat 53
#define sys_fchownat 54
#define sys_fchown 55
#define sys_openat 56
#define sys_close 57
#define sys_vhangup 58

/* fs/pipe.c */
#define sys_pipe2 59

/* fs/quota.c */
#define sys_quotactl 60

/* fs/readdir.c */
#define sys_getdents64 61

/* fs/read_write.c */
#define sys_llseek 62
#define sys_read 63
#define sys_write 64
#define sys_readv 65
#define sys_writev 66
#define sys_pread64 67
#define sys_pwrite64 68
#define sys_preadv 69
#define sys_pwritev 70

/* fs/sendfile.c */
#define sys_sendfile64 71

/* fs/select.c */
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_pselect6 72
#define sys_ppoll 73
#endif

/* fs/signalfd.c */
#define sys_signalfd4 74

/* fs/splice.c */
#define sys_vmsplice 75
#define sys_splice 76
#define sys_tee 77

/* fs/stat.c */
#define sys_readlinkat 78
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
#define sys_fstatat64 79
#define sys_fstat64 80
#endif

/* fs/sync.c */
#define sys_sync 81
#define sys_fsync 82
#define sys_fdatasync 83
#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
#define sys_sync_file_range2 84
#else
#define sys_sync_file_range 84
#endif

/* fs/timerfd.c */
#define sys_timerfd_create 85
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_timerfd_settime32 86
#define sys_timerfd_gettime32 87
#endif

/* fs/utimes.c */
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_utimensat_time32 88
#endif

/* kernel/acct.c */
#define sys_acct 89

/* kernel/capability.c */
#define sys_capget 90
#define sys_capset 91

/* kernel/exec_domain.c */
#define sys_personality 92

/* kernel/exit.c */
#define sys_exit 93
#define sys_exit_group 94
#define sys_waitid 95

/* kernel/fork.c */
#define sys_set_tid_address 96
#define sys_unshare 97

/* kernel/futex.c */
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_futex 98
#endif
#define sys_set_robust_list 99
#define sys_get_robust_list 100

/* kernel/hrtimer.c */
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_nanosleep 101
#endif

/* kernel/itimer.c */
#define sys_getitimer 102
#define sys_setitimer 103

/* kernel/kexec.c */
#define sys_kexec_load 104

/* kernel/module.c */
#define sys_init_module 105
#define sys_delete_module 106

/* kernel/posix-timers.c */
#define sys_timer_create 107
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_timer_gettime32 108
#endif
#define sys_timer_getoverrun 109
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_timer_settime 110
#endif
#define sys_timer_delete 111
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_clock_settime32 112
#define sys_clock_gettime 113
#define sys_clock_getres 114
#define sys_clock_nanosleep 115
#endif

/* kernel/printk.c */
#define sys_syslog 116

/* kernel/ptrace.c */
#define sys_ptrace 117

/* kernel/sched/core.c */
#define sys_sched_setparam 118
#define sys_sched_setscheduler 119
#define sys_sched_getscheduler 120
#define sys_sched_getparam 121
#define sys_sched_setaffinity 122
#define sys_sched_getaffinity 123
#define sys_sched_yield 124
#define sys_sched_get_priority_max 125
#define sys_sched_get_priority_min 126
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_sched_rr_get_interval 127
#endif

/* kernel/signal.c */
#define sys_restart_syscall 128
#define sys_kill 129
#define sys_tkill 130
#define sys_tgkill 131
#define sys_sigaltstack 132
#define sys_rt_sigsuspend 133
#define sys_rt_sigaction 134
#define sys_rt_sigprocmask 135
#define sys_rt_sigpending 136
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_rt_sigtimedwait 137
#endif
#define sys_rt_sigqueueinfo 138
#define sys_rt_sigreturn 139

/* kernel/sys.c */
#define sys_setpriority 140
#define sys_getpriority 141
#define sys_reboot 142
#define sys_setregid 143
#define sys_setgid 144
#define sys_setreuid 145
#define sys_setuid 146
#define sys_setresuid 147
#define sys_getresuid 148
#define sys_setresgid 149
#define sys_getresgid 150
#define sys_setfsuid 151
#define sys_setfsgid 152
#define sys_times 153
#define sys_setpgid 154
#define sys_getpgid 155
#define sys_getsid 156
#define sys_setsid 157
#define sys_getgroups 158
#define sys_setgroups 159
#define sys_newuname 160
#define sys_sethostname 161
#define sys_setdomainname 162

#ifdef __ARCH_WANT_SET_GET_RLIMIT
/* getrlimit and setrlimit are superseded with prlimit64 */
#define sys_getrlimit 163
#define sys_setrlimit 164
#endif

#define sys_getrusage 165
#define sys_umask 166
#define sys_prctl 167
#define sys_getcpu 168

/* kernel/time.c */
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_gettimeofday 169
#define sys_settimeofday 170
#define sys_adjtimex 171
#endif

/* kernel/timer.c */
#define sys_getpid 172
#define sys_getppid 173
#define sys_getuid 174
#define sys_geteuid 175
#define sys_getgid 176
#define sys_getegid 177
#define sys_gettid 178
#define sys_sysinfo 179

/* ipc/mqueue.c */
#define sys_mq_open 180
#define sys_mq_unlink 181
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_mq_timedsend 182
#define sys_mq_timedreceive 183
#endif
#define sys_mq_notify 184
#define sys_mq_getsetattr 185

/* ipc/msg.c */
#define sys_msgget 186
#define sys_msgctl 187
#define sys_msgrcv 188
#define sys_msgsnd 189

/* ipc/sem.c */
#define sys_semget 190
#define sys_semctl 191
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_semtimedop 192
#endif
#define sys_semop 193

/* ipc/shm.c */
#define sys_shmget 194
#define sys_shmctl 195
#define sys_shmat 196
#define __NR_shmdt 197

/* net/socket.c */
#define sys_socket 198
#define sys_socketpair 199
#define sys_bind 200
#define sys_listen 201
#define sys_accept 202
#define sys_connect 203
#define sys_getsockname 204
#define sys_getpeername 205
#define sys_sendto 206
#define sys_recvfrom 207
#define sys_setsockopt 208
#define sys_getsockopt 209
#define sys_shutdown 210
#define sys_sendmsg 211
#define sys_recvmsg 212

/* mm/filemap.c */
#define sys_readahead 213

/* mm/nommu.c, also with MMU */
#define sys_brk 214
#define sys_munmap 215
#define sys_mremap 216

/* security/keys/keyctl.c */
#define sys_add_key 217
#define sys_request_key 218
#define sys_keyctl 219

/* arch/example/kernel/sys_example.c */
#define sys_clone 220
#define sys_execve 221

#define sys_mmap 222
/* mm/fadvise.c */
#define sys_fadvise64_64 223

/* mm/, CONFIG_MMU only */
#ifndef __ARCH_NOMMU
#define sys_swapon 224
#define sys_swapoff 225
#define sys_mprotect 226
#define sys_msync 227
#define sys_mlock 228
#define sys_munlock 229
#define sys_mlockall 230
#define sys_munlockall 231
#define sys_mincore 232
#define sys_madvise 233
#define sys_remap_file_pages 234
#define sys_mbind 235
#define sys_get_mempolicy 236
#define sys_set_mempolicy 237
#define sys_migrate_pages 238
#define sys_move_pages 239
#endif

#define sys_rt_tgsigqueueinfo 240
#define sys_perf_event_open 241
#define sys_accept4 242
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_recvmmsg 243
#endif

/*
 * Architectures may provide up to 16 syscalls of their own
 * starting with this value.
 */
#define __NR_arch_specific_syscall 244

#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_wait4 260
#endif
#define sys_prlimit64 261
#define sys_fanotify_init 262
#define sys_fanotify_mark 263
#define sys_name_to_handle_at         264
#define sys_open_by_handle_at         265
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_clock_adjtime32 266
#endif
#define sys_syncfs 267
#define sys_setns 268
#define sys_sendmmsg 269
#define sys_process_vm_readv 270
#define sys_process_vm_writev 271
#define sys_kcmp 272
#define sys_finit_module 273
#define sys_sched_setattr 274
#define sys_sched_getattr 275
#define sys_renameat2 276
#define sys_seccomp 277
#define sys_getrandom 278
#define sys_memfd_create 279
#define sys_bpf 280
#define sys_execveat 281
#define sys_userfaultfd 282
#define sys_membarrier 283
#define sys_mlock2 284
#define sys_copy_file_range 285
#define sys_preadv2 286
#define sys_pwritev2 287
#define sys_pkey_mprotect 288
#define sys_pkey_alloc 289
#define sys_pkey_free 290
#define sys_statx 291
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define sys_io_pgetevents 292
#endif
#define sys_rseq 293
#define sys_kexec_file_load 294
/* 295 through 402 are unassigned to sync up with generic numbers, don't use */
#if __BITS_PER_LONG == 32
#define sys_clock_gettime 403
#define sys_clock_settime 404
#define sys_clock_adjtime 405
#define sys_clock_getres 406
#define sys_clock_nanosleep 407
#define sys_timer_gettime 408
#define sys_timer_settime 409
#define sys_timerfd_gettime 410
#define sys_timerfd_settime 411
#define sys_utimensat 412
#define sys_pselect6 413
#define sys_ppoll 414
#define sys_io_pgetevents 416
#define sys_recvmmsg 417
#define sys_mq_timedsend 418
#define sys_mq_timedreceive 419
#define sys_semtimedop 420
#define sys_rt_sigtimedwait 421
#define sys_futex 422

#define sys_sched_rr_get_interval 423
#endif

#define sys_pidfd_send_signal 424
#define sys_io_uring_setup 425
#define sys_io_uring_enter 426
#define sys_io_uring_register 427
#define sys_open_tree 428
#define sys_move_mount 429
#define sys_fsopen 430
#define sys_fsconfig 431
#define sys_fsmount 432
#define sys_fspick 433
#define sys_pidfd_open 434
#ifdef __ARCH_WANT_SYS_CLONE3
#define sys_clone3 435
#endif
#define sys_close_range 436

#define sys_openat2 437
#define sys_pidfd_getfd 438
#define sys_faccessat2 439
#define sys_process_madvise 440

#undef __NR_syscalls
#define __NR_syscalls 441

#endif /* __X86_64_SYSCALL_H */
