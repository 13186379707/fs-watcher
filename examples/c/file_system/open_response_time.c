#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <microhttpd.h>
#include <pthread.h>
#include <string.h>
#include "open_response_time.skel.h"
#include "open_response_time.h"

// 全局变量存储最新的10条事件（示例容量，可调整）
#define MAX_EVENTS 10
struct event latest_events[MAX_EVENTS];
pthread_mutex_t events_mutex = PTHREAD_MUTEX_INITIALIZER;
int event_index = 0;
static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static enum MHD_Result http_handler(void *cls, struct MHD_Connection *connection, const char *url, 
            const char *method,const char *version, const char *upload_data,size_t *upload_data_size, void **con_cls) {
    // 使用动态分配确保内存生命周期
    char *response = malloc(4096);
    if (!response) return MHD_NO;

    int offset = 0;
    offset += snprintf(response + offset, 4096 - offset,
        "# HELP open_syscall_duration_ns Duration of open syscalls in microseconds\n"
        "# TYPE open_syscall_duration_ns gauge\n");

    pthread_mutex_lock(&events_mutex);
    for (int i = 0; i < MAX_EVENTS; i++) {
        if (latest_events[i].pid == 0) continue;
        offset += snprintf(response + offset, 4096 - offset,
            "open_syscall_duration_ns{pid=\"%d\",comm=\"%s\"} %llu\n",
            latest_events[i].pid, latest_events[i].comm, latest_events[i].duration_ns);
    }
    pthread_mutex_unlock(&events_mutex);

    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(
        offset, (void *)response, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(mhd_response, "Content-Type", "text/plain");
    return MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
}

// 事件处理函数（更新最新事件）
static int handle_event(void *ctx, void *data, unsigned long data_sz) {
    const struct event *e = data;
    pthread_mutex_lock(&events_mutex);
    latest_events[event_index % MAX_EVENTS] = *e;  // 循环写入
    event_index++;
    pthread_mutex_unlock(&events_mutex);
    return 0;
}

/*
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}
*/

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct open_response_time_bpf *skel;
    struct MHD_Daemon *daemon;
	int err;

    // 启动 HTTP 服务（端口8080）
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 8080, 
        NULL, NULL, &http_handler, NULL, MHD_OPTION_END);
    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return 1;
    }

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* 打开BPF应用程序 */
	skel = open_response_time_bpf__open();
	if (!skel) {
	    fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	/* 加载并验证BPF程序 */
	err = open_response_time_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	
	/* 附加跟踪点处理程序 */
	err = open_response_time_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	/* 设置环形缓冲区轮询 */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	/* 处理事件 */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
	}
	
/* 卸载BPF程序 */
cleanup:
    MHD_stop_daemon(daemon);
	ring_buffer__free(rb);
	open_response_time_bpf__destroy(skel);
	
	return err < 0 ? -err : 0;
}