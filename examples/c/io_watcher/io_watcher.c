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
#include "io_watcher.skel.h"
#include "io_watcher.h"

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
    bool io_queue;
	bool show;
    pid_t fs_pid;
	char hostname[13];
    //enum EventType event_type;
} env = {
    .io_queue = false,
	.show = false,
	.fs_pid = -1,
	.hostname = "",
    //.event_type = NONE_TYPE,
};

const char *argp_program_version = "io_watcher 1.0";
const char *argp_program_bug_address = "<13186379707@163.com>";
const char argp_program_doc[] = "BPF program used for monitoring FileSystem information\n";
int option_selected = 0;  // 功能标志变量,确保激活子功能
static const struct argp_option opts[] = {
    {"io_queue", 'q', 0, 0, "Trace io queue"},
	{"show", 's', NULL, 0, "Visual display"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
		case 's':
			env.show = true;
			break;
		case 'q':
			env.io_queue = true;
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
    "|_   _|/ ____ \\ \\ \\          / / \\|__   __/ ____| |  | | ____|  __ \\       \n"\
    "  | | | |    | |\\ \\   /\\   / / _ \\  | | | |    | |__| | |___| |__) |      \n"\
    "  | | | |    | |   \\ \\ /  \\ / / ___ \\ | | | |    |  __  |  ___|  __ <     \n"\
    " _| |_| |____| |  \\ V /\\ V / /   \\ \\| | | |____| |  | | |___| |  \\ \\    \n"\
    "|_____|\\______/     \\_/  \\_/_/     \\_\\_|  \\_____|_|  |_| ____|_|   \\_\\  \n\n"

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
	//if (level == LIBBPF_DEBUG && !env.debug)
    //    return 0;
    return vfprintf(stderr, format, args);
}

static int io_queue_rb_handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct io_queue* e = data;
	printf("ts:%llu\ttag:%d\tdev numer:%d:%d\t\ttotal requests:%llu\t wait requests:%llu\tmax queue length:%llu\n", e->ts, e->tag, e->dev_num.major, e->dev_num.minor, e->total_requests, e->waiting_requests, e->max_queue_length);
	
	return 0;
}

int main(int argc, char** argv)
{
	// 定义一个数据传输的缓冲区
	struct ring_buffer *io_queue_rb = NULL;
	struct io_watcher_bpf* skel;
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
	skel = io_watcher_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
		return 1;
	}
	/* Parameterize BPF code with parameter */
	skel->rodata->fs_pid = env.fs_pid;

	err = io_watcher_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton: %s\n", strerror(errno));
		goto cleanup;
	}

	err = io_watcher_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %s\n", strerror(errno));
		goto cleanup;
	}

    io_queue_rb = ring_buffer__new(bpf_map__fd(skel->maps.io_queue_rb), io_queue_rb_handle_event, NULL, NULL);
    if (!io_queue_rb) 
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
		if (env.io_queue)
			err = ring_buffer__poll(io_queue_rb, 100 /* timeout, ms */);
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
	if (io_queue_rb)
		ring_buffer__free(io_queue_rb);

	io_watcher_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}