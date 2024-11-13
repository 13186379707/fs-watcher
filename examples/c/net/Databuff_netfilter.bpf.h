// netfilter

#include "Databuff.bpf.h"

static __always_inline
int submit_nf_time(struct packet_tuple pkt_tuple, struct filtertime *tinfo, int rx)
{
    int time = 0;  // 初始化时间变量
    struct netfilter *message;  // 定义 netfilter 结构体的指针，用于存储数据
    
    // 从 BPF 环形缓冲区中保留一个消息空间
    message = (struct netfilter*)bpf_ringbuf_reserve(&netfilter_rb, sizeof(*message), 0);
    if (!message) {
        return 0;  // 如果未成功保留空间，则返回 0
    }

    // 填充消息结构体中的各个字段
    message->saddr = pkt_tuple.saddr;  // 源地址
    message->daddr = pkt_tuple.daddr;  // 目的地址
    message->sport = pkt_tuple.sport;  // 源端口
    message->dport = pkt_tuple.dport;  // 目的端口
    message->local_input_time = 0;  // 初始化本地输入时间
    message->pre_routing_time = 0;  // 初始化路由前时间
    message->local_out_time = 0;    // 初始化本地输出时间
    message->post_routing_time = 0; // 初始化路由后时间
    message->forward_time = 0;      // 初始化转发时间
    message->rx = rx;  // 设置数据包的传输方向

    // 如果数据包是接收方向 (rx == 1)
    if (rx == 1) {
        // 确保本地传递完成时间、本地传递时间和接收时间都存在
        if (tinfo->time[e_ip_local_deliver_finish] &&
            tinfo->time[e_ip_local_deliver] &&
            tinfo->time[e_ip_rcv]) {
            
            // 计算本地输入时间
            message->local_input_time = tinfo->time[e_ip_local_deliver_finish] - 
                                            tinfo->time[e_ip_local_deliver];
            // 计算路由前时间
            message->pre_routing_time = tinfo->time[e_ip_local_deliver] - 
                                            tinfo->time[e_ip_rcv];

            // 如果时间差为负值，表示时间错误，丢弃消息
            if ((int)message->local_input_time < 0 || (int)message->pre_routing_time < 0) {
                bpf_ringbuf_discard(message, 0);
                return 0;  // 返回 0 表示丢弃消息
            }
        }
    } else {
        // 如果数据包不是接收方向，可能是转发或发送方向
        // 确保相关时间存在
        if (tinfo->time[e_ip_local_deliver_finish] && 
            tinfo->time[e_ip_local_deliver] &&
            tinfo->time[e_ip_rcv] &&
            tinfo->time[e_ip_forward] &&
            tinfo->time[e_ip_output]) {

            // 计算本地输入时间
            message->local_input_time = tinfo->time[e_ip_local_deliver_finish] - 
                                            tinfo->time[e_ip_local_deliver];
            // 计算路由前时间
            message->pre_routing_time = tinfo->time[e_ip_local_deliver] - 
                                            tinfo->time[e_ip_rcv];
            // 计算转发时间
            u64 forward_time = tinfo->time[e_ip_output] - tinfo->time[e_ip_forward];

            // 如果转发时间为负值，丢弃消息
            if ((int)forward_time < 0) {
                bpf_ringbuf_discard(message, 0);
                return 0;
            }
            message->forward_time = forward_time;  // 设置转发时间
            message->rx = 2;  // 设置方向为转发
        }

        // 检查输出相关时间
        if (tinfo->time[e_ip_output] &&
            tinfo->time[e_ip_local_out] &&
            tinfo->time[e_ip_finish_output]) {
            
            // 计算本地输出时间
            message->local_out_time = tinfo->time[e_ip_output] - 
                                        tinfo->time[e_ip_local_out];
            // 计算路由后时间
            message->post_routing_time = tinfo->time[e_ip_finish_output] - 
                                            tinfo->time[e_ip_output];

            // 如果时间差为负值，丢弃消息
            if ((int)message->local_out_time < 0 || (int)message->post_routing_time < 0) {
                bpf_ringbuf_discard(message, 0);
                return 0;
            }
        }
    }

    // 将消息提交到 BPF 环形缓冲区
    bpf_ringbuf_submit(message, 0);
    return 0;  // 返回 0 表示成功处理
}


// 这是注释
static __always_inline
int store_nf_time(struct sk_buff *skb, int hook) {
    // 通过数据包 skb 获取 IP 和 TCP 头部
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    
    // 定义 filtertime 结构体指针 tinfo 和初始化为 0 的 zero
    struct filtertime *tinfo, zero = {.init = {0}, .time={0}};
    
    // 本地接收，本地发出
    if(hook == e_ip_rcv || hook == e_ip_local_out) {
        // 在 BPF 映射中查找或初始化条目
        tinfo = (struct filtertime *)bpf_map_lookup_or_try_init(&netfilter_time, &skb, &zero);  
        if(tinfo == NULL)
            return 0; // 如果未找到对应的条目则返回 0
        
        // 初始化 tinfo->init 
        get_pkt_tuple(&tinfo->init, ip, tcp);
    } else {
        // 不是本地接收，本地发出。属于其他阶段,map中已经有了信息
        tinfo = (struct filtertime *)bpf_map_lookup_elem(&netfilter_time, &skb);
        if (tinfo == NULL)
            return 0; // 如果未找到对应条目则返回 0
    }                
    
    // 记录当前钩子时间
    tinfo->time[hook] = bpf_ktime_get_ns() / 1000;
    
    // 只有需要向上发送到传输层或者向下发送到邻居子系统的数据包才会调用 submit_nf_time 函数
    // 如果钩子是 e_ip_local_deliver_finish，提交记录并删除条目.传输层接收
    if(hook == e_ip_local_deliver_finish) {
        submit_nf_time(tinfo->init, tinfo, 1);
        bpf_map_delete_elem(&netfilter_time, &skb);
    }

    // 如果钩子是 e_ip_finish_output，提交记录并删除条目.邻居子系统接收
    if(hook == e_ip_finish_output) {
        submit_nf_time(tinfo->init, tinfo, 0);
        bpf_map_delete_elem(&netfilter_time, &skb);
    }

    return 0; // 正常结束
}