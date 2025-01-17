#ifndef COMMON_BPF_H
#define COMMON_BPF_H

#define FILTER(fs_pid)                                                 \
    if ((fs_pid) > 0 && (bpf_get_current_pid_tgid() >> 32) != (fs_pid)) { \
        return 0;                                                         \
    }

#endif /* COMMON_BPF_H */