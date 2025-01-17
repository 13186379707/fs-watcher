#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "fs_watcher.skel.h"
#include "fs_watcher.h"

// 检查具有给定 PID 的进程是否存在
int doesVmProcessExist(pid_t pid) {
    if (kill(pid, 0) == 0) {
        printf("Process %d exists.\n", pid);
        return 1;
    } else {
        perror("kill");
        return 0;
    }
}

// 定义env结构体，用来存储程序中的事件信息
static struct env {
    bool fs_monitor;
	bool event_monitor;
	bool chmod_event;
	bool chown_event;
	bool ftruncate_event;
	bool mount_event;
	bool open_event;
	bool read_event;
	bool rename_event;
	bool unlink_event;
	bool write_event;
    bool show;
	bool debug;
    pid_t fs_pid;
	char hostname[13];
    //enum EventType event_type;
} env = {
    .fs_monitor = false,
	.event_monitor = false,
	.chmod_event = false,
	.chown_event = false,
	.ftruncate_event = false,
	.mount_event = false,
	.open_event = false,
	.read_event = false,
	.rename_event = false,
	.unlink_event = false,
	.write_event = false,
    .show = false,
	.debug = false,
	.fs_pid = -1,
	.hostname = "",
    //.event_type = NONE_TYPE,
};

const char *argp_program_version = "fs_watcher 1.0";
const char *argp_program_bug_address = "<13186379707@163.com>";
const char argp_program_doc[] = "BPF program used for monitoring FileSystem information\n";
int option_selected = 0;  // 功能标志变量,确保激活子功能
static const struct argp_option opts[] = {
    {"fs_monitor", 'F', 0, 0, "Set to trace fs_monitor"},
    {"event_monitor", 'a', 0, 0, "Set to trace all event_monitor"},
	{"chmod_event", 'C', 0, 0, "Set to trace chmod events" },
	{"chown_event", 'c', 0, 0, "Set to trace chown events" },
	{"ftruncate_event", 'f', 0, 0, "Set to trace ftruncate events" },
	{"mount_event", 'm', 0, 0, "Set to trace mount events" },
	{"open_event", 'o', 0, 0, "Set to trace open events" },
	{"read_event", 'r', 0, 0, "Set to trace read events" },
	{"rename_event", 'R', 0, 0, "Set to trace rename events" },
	{"unlink_event", 'u', 0, 0, "Set to trace unlink events" },
	{"write_event", 'w', 0, 0, "Set to trace write events" },
	{"debug", 'd', NULL, 0, "printf eBPF debug information"},
	{"show", 's', NULL, 0, "Visual display"},
	{"fs_pid", 'p', "PID", 0, "Specify the virtual machine pid to monitor."},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
		case 's':
			env.show = true;
			break;
    	case 'F':
        	env.fs_monitor = true;
        	break;
    	case 'a':
        	env.event_monitor = true;
        	break;
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case 'd':
			env.debug = true;
			break;
		case 'C':
			env.chmod_event = true;
			break;
		case 'c':
			env.chown_event = true;
			break;
		case 'f':
			env.ftruncate_event = true;
			break;
		case 'm':
			env.mount_event = true;
			break;
		case 'o':
			env.open_event = true;
			break;
		case 'r':
			env.read_event = true;
			break;
		case 'R':
			env.rename_event = true;
			break;
		case 'u':
			env.unlink_event = true;
			break;
		case 'w':
			env.write_event = true;
			break;
		case 'p':
			env.fs_pid = strtol(arg, NULL, 10);
			if (env.fs_pid <= 0 || doesVmProcessExist(env.fs_pid) == 0) {
				fprintf(stderr, "Invalid fs_pid: %s\n", arg);
				argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
			}
			break;
		case ARGP_KEY_ARG:
            argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            break;
    	default:
        	return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
// 定义解析参数的处理函数
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

void clear_screen() {
    // ANSI 转义序列清屏
    printf("\033[H\033[J");
}

#define LOGO_STRING                                                                   \
    " _____  _____  __            ___  _______ _____ _    _ _____ _____            \n"\
    "| ____|/ ____| \\ \\          / / \\|__   __/ ____| |  | | ____|  __ \\       \n"\
    "| |___| (___    \\ \\   /\\   / / _ \\  | | | |    | |__| | |___| |__) |      \n"\
    "|  ___|\\___ \\    \\ \\ /  \\ / / ___ \\ | | | |    |  __  |  ___|  __ <     \n"\
    "| |    ____) |    \\ V /\\ V / /   \\ \\| | | |____| |  | | |___| |  \\ \\    \n"\
    "|_|   |_____/      \\_/  \\_/_/     \\_\\_|  \\_____|_|  |_| ____|_|   \\_\\  \n\n"

void print_logo() {
    char *logo = LOGO_STRING;
    int i = 0;
    FILE *lolcat_pipe = popen("/usr/games/lolcat", "w");
    if (lolcat_pipe == NULL) {
        printf("Error: Unable to execute lolcat command.\n");
        return;
    }
    // 像lolcat管道逐个字符写入字符串
    while (logo[i] != '\0') {
        fputc(logo[i], lolcat_pipe);
        fflush(lolcat_pipe); // 刷新管道，确保字符被立即发送给lolcat
        usleep(150);
        i++;
    }

    pclose(lolcat_pipe);
}

static volatile bool exiting = false;
// 设置信号来控制是否打印信息
static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
	if (level == LIBBPF_DEBUG && !env.debug)
        return 0;
    return vfprintf(stderr, format, args);
}

static int write_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:write\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int unlink_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:unlink\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int rename_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:rename\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int read_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:read\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int open_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:open\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int mount_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:mount\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int ftruncate_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:ftruncate\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int chown_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:chmod\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int chmod_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;

	if (strcmp(e->comm, "fs_watcher"))
		printf("opcode:chmod\tpid:%-10d\tduration_time(ms):%-15llu\tcomm:%-15s\n", e->pid, e->duration_ns, e->comm);
	
	return 0;
}

static int rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct syscall_events *e = data;
	switch (e->syscall_id) {
		case sys_epoll_create1 :
		case sys_timerfd_create :
		case sys_timer_create :
		case sys_memfd_create :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:create\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_openat :
		case sys_mq_open :
		case sys_perf_event_open :
		case sys_open_by_handle_at :
		case sys_open_tree :
		case sys_fsopen :
		case sys_pidfd_open :
		case sys_openat2 :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:open\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_read :
		case sys_readv :
		case sys_pread64 :
		case sys_preadv :
		case sys_readlinkat :
		case sys_readahead :
		case sys_process_vm_readv :
		case sys_preadv2 :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:read\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_write :
		case sys_writev :
		case sys_pwrite64 :
		case sys_pwritev :
		case sys_process_vm_writev :
		case sys_pwritev2 :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:write\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_unlinkat :
		case sys_mq_unlink :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:unlink\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_renameat2 :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:rename\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_ftruncate64 :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:ftruncate\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_fchmod :
		case sys_fchmodat :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:chmod\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		case sys_fchownat :
		case sys_fchown :
			printf("pid:%-10d\tdelay:%-10llu\tcomm:%-15s\tsyscall_id:%-5llu\tevent:chown\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
		default:
			//printf("pid:%-10d delay:%-10llu comm:%-15s syscall_id:%-5llu syscall:other\n", e->pid, e->delay, e->comm, e->syscall_id);
			break;
        }
	
	return 0;
}

static void pb_handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event_t* e = data;
	switch (e->op)
	{
	case 1:
		printf("pid:%-10d opcode:opens  fliename:%-30s comm:%-15s is_fd:%d\n", e->pid, e->fname, e->comm, e->is_fd);
		break;

	case 2:
		printf("pid:%-10d opcode:reads  fliename:%-30s comm:%-15s is_fd:%d\n", e->pid, e->fname, e->comm, e->is_fd);
		break;
	
	case 3:
		printf("pid:%-10d opcode:writes fliename:%-30s comm:%-15s is_fd:%d\n", e->pid, e->fname, e->comm, e->is_fd);
		break;
	}
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char** argv)
{
	// 定义一个数据传输的缓冲区
	struct perf_buffer *pb = NULL;
	struct ring_buffer *rb = NULL;
	struct ring_buffer *chmod_rb = NULL;
	struct ring_buffer *chown_rb = NULL;
	struct ring_buffer *ftruncate_rb = NULL;
	struct ring_buffer *mount_rb = NULL;
	struct ring_buffer *open_rb = NULL;
	struct ring_buffer *read_rb = NULL;
	struct ring_buffer *rename_rb = NULL;
	struct ring_buffer *unlink_rb = NULL;
	struct ring_buffer *write_rb = NULL;
	struct fs_watcher_bpf* skel;
	int err;
	/*解析命令行参数*/
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	/*设置libbpf的错误和调试信息回调*/
	libbpf_set_print(libbpf_print_fn);
    /* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);
	/* Open BPF application */
	skel = fs_watcher_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
		return 1;
	}
	/* Parameterize BPF code with parameter */
	skel->rodata->fs_pid = env.fs_pid;

	err = fs_watcher_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton: %s\n", strerror(errno));
		goto cleanup;
	}

	err = fs_watcher_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %s\n", strerror(errno));
		goto cleanup;
	}

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                      pb_handle_event, handle_lost_events, NULL, NULL);
    if (!pb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
		goto cleanup;
	}
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), rb_handle_event, NULL, NULL);
    if (!rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	chmod_rb = ring_buffer__new(bpf_map__fd(skel->maps.chmod_rb), chmod_rb_handle_event, NULL, NULL);
    if (!chmod_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	chown_rb = ring_buffer__new(bpf_map__fd(skel->maps.chown_rb), chown_rb_handle_event, NULL, NULL);
    if (!chown_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	ftruncate_rb = ring_buffer__new(bpf_map__fd(skel->maps.ftruncate_rb), ftruncate_rb_handle_event, NULL, NULL);
    if (!ftruncate_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	mount_rb = ring_buffer__new(bpf_map__fd(skel->maps.mount_rb), mount_rb_handle_event, NULL, NULL);
    if (!mount_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	open_rb = ring_buffer__new(bpf_map__fd(skel->maps.open_rb), open_rb_handle_event, NULL, NULL);
    if (!open_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	read_rb = ring_buffer__new(bpf_map__fd(skel->maps.read_rb), read_rb_handle_event, NULL, NULL);
    if (!read_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	rename_rb = ring_buffer__new(bpf_map__fd(skel->maps.rename_rb), rename_rb_handle_event, NULL, NULL);
    if (!rename_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	unlink_rb = ring_buffer__new(bpf_map__fd(skel->maps.unlink_rb), unlink_rb_handle_event, NULL, NULL);
    if (!unlink_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }
	write_rb = ring_buffer__new(bpf_map__fd(skel->maps.write_rb), write_rb_handle_event, NULL, NULL);
    if (!write_rb) 
	{
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet): %s\n", strerror(errno));
        goto cleanup;
    }

	if (!env.show)
        print_logo();

	//实现刷屏操作
    //clear_screen();    
    //fflush(stdout);
	
	while (!exiting) {
		if (env.fs_monitor)
			err = perf_buffer__poll(pb, -1);
		if (env.event_monitor)
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (env.chmod_event)
			err = ring_buffer__poll(chmod_rb, 100 /* timeout, ms */);
		if (env.chown_event)
			err = ring_buffer__poll(chown_rb, 100 /* timeout, ms */);
		if (env.ftruncate_event)
			err = ring_buffer__poll(ftruncate_rb, 100 /* timeout, ms */);
		if (env.mount_event)
			err = ring_buffer__poll(mount_rb, 100 /* timeout, ms */);
		if (env.open_event)
			err = ring_buffer__poll(open_rb, 100 /* timeout, ms */);
		if (env.read_event)
			err = ring_buffer__poll(read_rb, 100 /* timeout, ms */);
		if (env.rename_event)
			err = ring_buffer__poll(rename_rb, 100 /* timeout, ms */);
		if (env.unlink_event)
			err = ring_buffer__poll(unlink_rb, 100 /* timeout, ms */);
		if (env.write_event)
			err = ring_buffer__poll(write_rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);	
	}

cleanup:
	if (pb)
		perf_buffer__free(pb);
	if (rb)
		ring_buffer__free(rb);
	if (chmod_rb)
		ring_buffer__free(chmod_rb);
	if (chown_rb)
		ring_buffer__free(chown_rb);
	if (ftruncate_rb)
		ring_buffer__free(ftruncate_rb);
	if (mount_rb)
		ring_buffer__free(mount_rb);
	if (open_rb)
		ring_buffer__free(open_rb);
	if (read_rb)
		ring_buffer__free(read_rb);
	if (rename_rb)
		ring_buffer__free(rename_rb);
	if (unlink_rb)
		ring_buffer__free(unlink_rb);
	if (write_rb)
		ring_buffer__free(write_rb);

	fs_watcher_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}