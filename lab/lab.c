#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#define ECN_RING_THRESHOLD ((DEV_RING_SIZE * 3) / 4)
#define CC_GAP_STEP_US 5
#define CC_GAP_MAX_US 2000

/*======================================================================
 *  实验七：在网计算  —— 学生模板
 *
 *  下面带有
 *      start of your code  ...  end of your code
 *  标记的函数体需要你来补全。其余部分（libpcap 收发、接收缓冲区、各类
 *  初始化、转发表/聚合器数据结构、辅助函数）已经给出，可直接使用：
 *
 *    辅助/IO（已给）：
 *      now_us()                                  取当前时间(微秒)
 *      build_frame(...)                          组装一帧 MTP 报文
 *      conn_send(cn, seq, ack_flag, op, buf, n)  在某连接上发一个分组
 *      conn_pop(cn, &msg)                        从某连接接收缓冲区取一个分组(非阻塞)
 *      router_forward(frame, len, dst_ip)        路由器按目的 IP 转发一帧
 *      dev_pop(&pk)                              路由器从共享缓冲区取一帧(非阻塞)
 *      broadcast_slot(seq)                       路由器把某聚合完成的 slot 广播给所有连接
 *
 *  完整正确实现见 ../answer/lab.c（仅供对照，请独立完成）。
 *====================================================================*/

/*======================================================================
 *  通用工具（已给）
 *====================================================================*/

static int g_n = 0;
static int rank_of_ip(uint32_t ip);

uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* 标准 Internet 校验和（16 位反码求和） */
static uint16_t ip_checksum(const void *data, int len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    int i;
    for (i = 0; i + 1 < len; i += 2)
        sum += (uint16_t)((p[i] << 8) | p[i + 1]);
    if (len & 1)
        sum += (uint16_t)(p[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

/* 组装一帧 MTP 报文到 buf，返回总长度。 */
static int build_frame_ex(uint8_t *buf,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint32_t src_id, uint32_t dst_id,
                          uint16_t block_id, uint16_t count,
                          uint32_t seq_for_transport,
                          uint8_t is_ack, uint8_t is_fetch, uint8_t resend,
                          const void *payload, uint16_t plen) {
    eth_header_t *eth = (eth_header_t *)buf;
    memset(eth->dst_mac, 0xff, 6);
    memset(eth->src_mac, 0x00, 6);
    eth->ether_type = htons(ETH_TYPE_IP);

    ip_header_t *ip = (ip_header_t *)(buf + sizeof(eth_header_t));
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_len = htons(sizeof(ip_header_t) + sizeof(mtp_header_t) + plen);
    ip->id = htons((uint16_t)seq_for_transport);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTO_MTP;
    ip->checksum = 0;
    ip->src_ip = src_ip;
    ip->dst_ip = dst_ip;
    ip->checksum = htons(ip_checksum(ip, sizeof(ip_header_t)));

    mtp_header_t *mtp = (mtp_header_t *)(buf + sizeof(eth_header_t) + sizeof(ip_header_t));
    mtp->src_id = htonl(src_id);
    mtp->dst_id = htonl(dst_id);
    mtp->block_id = htons(block_id);
    mtp->count = htons(count);
    mtp->is_ack = is_ack;
    mtp->is_fetch = is_fetch;
    mtp->ecn = 0;
    mtp->resend = resend;

    if (plen > 0 && payload)
        memcpy(buf + HDR_LEN, payload, plen);

    return (int)(HDR_LEN + plen);
}

static int build_frame(uint8_t *buf,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t local_conn_id, uint32_t seq_for_transport,
                       uint8_t is_ack, uint8_t op,
                       const void *payload, uint16_t plen) {
    (void)local_conn_id;
    (void)op;
    int src_rank = rank_of_ip(src_ip);
    int dst_rank = rank_of_ip(dst_ip);
    uint16_t count = (uint16_t)(is_ack ? 0 : (g_n > 0 ? g_n - 1 : 0));
    return build_frame_ex(buf, src_ip, dst_ip,
                          (uint32_t)(src_rank >= 0 ? src_rank : 0),
                          (uint32_t)(dst_rank >= 0 ? dst_rank : 0),
                          0, count, seq_for_transport,
                          is_ack, 0, 0, payload, plen);
}

/*======================================================================
 *  主机端
 *====================================================================*/
// 通信组，每个 rank 的静态配置信息，每一项包括：
//      - rank
//      - host_name
//      - host_iface
//      - router_iface
//      - host_ip
static config_entry_t g_cfg[MAX_GROUP_SIZE];
// 组数
// 自身的rank
static int            g_rank = -1;
static uint32_t       g_my_ip = 0;
// 抓包/发包句柄
static pcap_t        *g_host_handle = NULL;

/* 简化图模型：4 个顶点全连接，rank 就是 vertex id。 */
static int rank_of_ip(uint32_t ip) {
    for (int i = 0; i < g_n; i++)
        if (g_cfg[i].host_ip == ip) return g_cfg[i].rank;
    return -1;
}
static pthread_mutex_t g_tx_lock = PTHREAD_MUTEX_INITIALIZER;
//当前主机已经初始化的连接”。每个 conn_t 里有：
//    - in_use：这一项是否有效
//    - conn_id：本地连接标识
//    - local_ip / remote_ip：本端和对端 IP
//    - queue[RXQ_SIZE]：这条连接的接收缓冲区
//    - head / tail：环形队列读写位置
//    - lock：保护这条连接队列的锁
static conn_t         g_conns[MAX_CONNS];
static int            g_conn_count = 0;

static conn_t *find_conn_by_remote(uint32_t remote_ip) {
    for (int i = 0; i < g_conn_count; i++) {
        if (!g_conns[i].in_use) continue;
        if (g_conns[i].local_ip == g_my_ip && g_conns[i].remote_ip == remote_ip)
            return &g_conns[i];
    }
    return NULL;
}

typedef struct {
    int active;
    const uint8_t *buf;
    uint32_t npkts;
    uint8_t op;
    uint8_t *acked;
    uint32_t *send_mask;
    uint32_t peer_mask;
    volatile uint8_t ecn_pending;
    uint32_t gap_us;
} send_ctx_t;

static send_ctx_t g_send_ctx[MAX_CONNS];
static void conn_send(conn_t *cn, uint32_t seq, uint8_t ack_flag, uint8_t op,
                      const void *payload, uint16_t plen);

static void mark_all_senders_ecn(void) {
    for (int i = 0; i < g_conn_count; i++) {
        if (g_send_ctx[i].active)
            g_send_ctx[i].ecn_pending = 1;
    }
}

static send_ctx_t *active_send_ctx(void) {
    for (int i = 0; i < g_conn_count; i++) {
        if (g_send_ctx[i].active)
            return &g_send_ctx[i];
    }
    return NULL;
}

static void send_ack_to_neighbors(uint32_t seq, uint8_t op) {
    for (int r = 0; r < g_n; r++) {
        if (r == g_rank) continue;
        conn_t *peer = find_conn_by_remote(g_cfg[r].host_ip);
        if (peer)
            conn_send(peer, seq, 1, op, NULL, 0);
    }
}

static const uint8_t *g_local_src_buf = NULL;
static uint32_t g_local_src_npkts = 0;
static uint8_t g_local_src_op = 0;

void register_local_source(const void *buf, uint32_t size, uint8_t op) {
    g_local_src_buf = (const uint8_t *)buf;
    g_local_src_npkts = size / PAYLOAD_LEN;
    g_local_src_op = op;
}

void clear_local_source(void) {
    g_local_src_buf = NULL;
    g_local_src_npkts = 0;
    g_local_src_op = 0;
}

/* 经 pcap 发送一帧（多线程发送加锁）。已给。 */
// 发到router对端
static void host_inject(uint8_t *frame, int len) {
    pthread_mutex_lock(&g_tx_lock);
    pcap_inject(g_host_handle, frame, len);
    pthread_mutex_unlock(&g_tx_lock);
}

/* 在某个 block 通道上发送一个 MTP 分组。 */
static void conn_send_ex(conn_t *cn, uint32_t seq, uint8_t ack_flag, uint8_t op,
                         uint8_t is_fetch, uint8_t resend,
                         const void *payload, uint16_t plen) {
    (void)op;
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    int src_rank = rank_of_ip(cn->local_ip);
    int dst_rank = rank_of_ip(cn->remote_ip);
    uint16_t count = (uint16_t)(ack_flag ? 0 : (g_n > 0 ? g_n - 1 : 0));
    int len = build_frame_ex(frame, cn->local_ip, cn->remote_ip,
                             (uint32_t)(src_rank >= 0 ? src_rank : 0),
                             (uint32_t)(dst_rank >= 0 ? dst_rank : 0),
                             0, count, seq,
                             ack_flag, is_fetch, resend, payload, plen);
    host_inject(frame, len);
}

static void conn_send(conn_t *cn, uint32_t seq, uint8_t ack_flag, uint8_t op,
                      const void *payload, uint16_t plen) {
    conn_send_ex(cn, seq, ack_flag, op, 0, 0, payload, plen);
}

/* 后台接收线程：抓本机网卡进入的帧，按 conn_id 分发到对应连接的接收缓冲区。已给。 */
// 主机内部的分发
static void *host_rx_thread(void *arg) {
    (void)arg;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;
    // 从网卡持续抓包
    while ((rc = pcap_next_ex(g_host_handle, &hdr, &pkt)) >= 0) {
        if (rc == 0) continue;
        // 过短
        if (hdr->caplen < HDR_LEN) continue;
        // 非ip
        const eth_header_t *eth = (const eth_header_t *)pkt;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;
        // 非mtp
        const ip_header_t *ip = (const ip_header_t *)(pkt + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;
        // 自身
        if (ip->src_ip == g_my_ip) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        const mtp_header_t *mtp =
            (const mtp_header_t *)(pkt + sizeof(eth_header_t) + ip_ihl);
        int plen = ntohs(ip->total_len) - ip_ihl - (int)sizeof(mtp_header_t);
        if (plen < 0) plen = 0;
        if (plen > PAYLOAD_LEN) plen = PAYLOAD_LEN;
        // 按本地连接上下文分发，不把 block_id 当作 conn_id 使用
        conn_t *cn = NULL;
        for (int i = 0; i < g_conn_count; i++) {
            if (!g_conns[i].in_use) continue;
            if (g_conns[i].local_ip != ip->dst_ip) continue;
            if (g_conns[i].remote_ip == ip->src_ip ||
                (ip->src_ip == 0 && g_conns[i].remote_ip == 0)) {
                cn = &g_conns[i];
                break;
            }
        }
        if (!cn) continue;
        // 放进该连接的接收队列
        pthread_mutex_lock(&cn->lock);
        int nh = (cn->head + 1) % RXQ_SIZE;
        // 如果队列满了丢弃
        if (nh != cn->tail) {
            rx_msg_t *m = &cn->queue[cn->head];
            m->src_id = ntohl(mtp->src_id);
            m->dst_id = ntohl(mtp->dst_id);
            m->block_id = ntohs(mtp->block_id);
            m->count = ntohs(mtp->count);
            m->seq_num = ntohs(ip->id);
            m->payload_len = (uint16_t)plen;
            m->is_ack = mtp->is_ack;
            m->is_fetch = mtp->is_fetch;
            m->ecn = mtp->ecn;
            m->resend = mtp->resend;
            /* 只拷贝实际存在的载荷字节（数据分组为 PAYLOAD_LEN，ACK 为 0） */
            if (plen > 0)
                memcpy(m->payload, pkt + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t), plen);
            cn->head = nh;
        }
        pthread_mutex_unlock(&cn->lock);
    }
    return NULL;
}

/* 从连接缓冲区取一个分组（非阻塞）；返回 1 成功，0 空。已给。 */
static int conn_pop(conn_t *cn, rx_msg_t *out) {
    int ok = 0;
    pthread_mutex_lock(&cn->lock);
    if (cn->tail != cn->head) {
        *out = cn->queue[cn->tail];
        cn->tail = (cn->tail + 1) % RXQ_SIZE;
        ok = 1;
    }
    pthread_mutex_unlock(&cn->lock);
    return ok;
}

/* 已给。 */
void init_host(config_entry_t *cfgs, int n, const char *host_name) {
    g_n = n;
    memcpy(g_cfg, cfgs, sizeof(config_entry_t) * n);

    for (int i = 0; i < n; i++)
        if (strcmp(cfgs[i].host_name, host_name) == 0) {
            g_rank = cfgs[i].rank;
            g_my_ip = cfgs[i].host_ip;
            break;
        }
    if (g_rank < 0) {
        fprintf(stderr, "init_host: host %s not found in config\n", host_name);
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = NULL;
    for (int i = 0; i < n; i++)
        if (cfgs[i].rank == g_rank) iface = cfgs[i].host_iface;

    g_host_handle = pcap_open_live(iface, DEV_BUF_SIZE, 1, 1, errbuf);
    if (!g_host_handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", iface, errbuf);
        exit(1);
    }
    pcap_setdirection(g_host_handle, PCAP_D_IN);

    pthread_t tid;
    pthread_create(&tid, NULL, host_rx_thread, NULL);
    printf("[host] %s rank=%d iface=%s ready\n", host_name, g_rank, iface);
    fflush(stdout);
}

/* 已给。 */
int init_conn(uint16_t conn_id, uint32_t local_ip, uint32_t remote_ip) {
    if (g_conn_count >= MAX_CONNS) return -1;
    conn_t *cn = &g_conns[g_conn_count];
    memset(cn, 0, sizeof(conn_t));
    cn->in_use = 1;
    cn->conn_id = conn_id;
    cn->local_ip = local_ip;
    cn->remote_ip = remote_ip;
    cn->head = cn->tail = 0;
    pthread_mutex_init(&cn->lock, NULL);
    return g_conn_count++;
}

/*------------- 可靠传输：发送端（待补全）-------------
 * 固定窗口 + 超时重传 + 独立 ACK（选择重传），初始序列号为 0。
 * 假设 size 是 PAYLOAD_LEN 的整数倍，故每个分组都是满载荷 PAYLOAD_LEN。 */
int m_send(int conn, const void *buf, uint32_t size, uint8_t op) {
    if (conn < 0 || conn >= g_conn_count) return -1;
    conn_t *cn = &g_conns[conn];
    uint32_t npkts = size / PAYLOAD_LEN;
    if (npkts == 0) return 0;

    /***********************
     * start of your code
     *
     * 提示（可用 conn_pop / conn_send / now_us）：
     *  1. 申请数组：acked[npkts]（是否已确认）、sent_at[npkts]（上次发送时间）；base=0
     *  2. while (base < npkts):
     *     a. 收 ACK：while conn_pop(cn,&m): 若 m.ack_flag==1 且 m.seq_num<npkts -> acked[seq]=1
     *     b. 滑动后沿：while base<npkts 且 acked[base] -> base++
     *     c. 发送窗口 [base, min(base+WINDOW, npkts)) 内的分组：
     *        若未 acked 且 (sent_at[s]==0 或 now-sent_at[s]>=RTO_US):
     *           conn_send(cn, s, 0, op, (uint8_t*)buf + s*PAYLOAD_LEN, PAYLOAD_LEN)
     *           sent_at[s] = now
     *     d. usleep(200) 避免空转
     *  3. 释放数组
     **********************/
    // 确认进度
    uint8_t *acked = calloc(npkts, sizeof(uint8_t));
    uint32_t *send_mask = calloc(npkts, sizeof(uint32_t));
    // 上次发送时间
    uint64_t *sent_at = calloc(npkts, sizeof(uint64_t));
    // 发送窗口左边界
    uint32_t base = 0;

    uint32_t peer_mask = 0;
    for (int r = 0; r < g_n; r++)
        if (r != g_rank) peer_mask |= (1u << r);

    if (!acked || !send_mask || !sent_at) {
        free(acked);
        free(send_mask);
        free(sent_at);
        return -1;
    }

    g_send_ctx[conn].active = 1;
    g_send_ctx[conn].buf = (const uint8_t *)buf;
    g_send_ctx[conn].npkts = npkts;
    g_send_ctx[conn].op = op;
    g_send_ctx[conn].acked = acked;
    g_send_ctx[conn].send_mask = send_mask;
    g_send_ctx[conn].peer_mask = peer_mask;
    g_send_ctx[conn].ecn_pending = 0;
    g_send_ctx[conn].gap_us = 100;

    uint64_t last_gap_adjust = now_us();
    uint64_t last_tx_at = 0;

    while (base < npkts) {
        uint64_t now = now_us();
        if (g_send_ctx[conn].ecn_pending) {
            uint32_t gap = g_send_ctx[conn].gap_us;
            g_send_ctx[conn].gap_us = gap == 0 ? 1 : (gap * 2 > CC_GAP_MAX_US ? CC_GAP_MAX_US : gap * 2);
            g_send_ctx[conn].ecn_pending = 0;
            last_gap_adjust = now;
        } else if (g_send_ctx[conn].gap_us > 0 && now - last_gap_adjust >= RTO_US) {
            g_send_ctx[conn].gap_us = (g_send_ctx[conn].gap_us > CC_GAP_STEP_US) ?
                                      (g_send_ctx[conn].gap_us - CC_GAP_STEP_US) : 0;
            last_gap_adjust = now;
        }
        // 推进窗口
        while (base < npkts && acked[base]) base++;
        // 新窗口
        uint32_t end = base + WINDOW;
        if (end > npkts) end = npkts;
        for (uint32_t s = base; s < end; s++) {
            uint64_t send_now = now_us();
            if (g_send_ctx[conn].gap_us > 0 && last_tx_at != 0 && send_now - last_tx_at < g_send_ctx[conn].gap_us)
                break;
            if (!acked[s] && (sent_at[s] == 0 || send_now - sent_at[s] >= RTO_US)) {
                uint8_t resend_flag = (sent_at[s] != 0);
                conn_send_ex(cn, s, 0, op, 0, resend_flag,
                             (const uint8_t *)buf + s * PAYLOAD_LEN, PAYLOAD_LEN);
                sent_at[s] = send_now;
                last_tx_at = send_now;
            }
        }
        if (base < npkts) usleep(200);
    }

    g_send_ctx[conn].active = 0;
    g_send_ctx[conn].buf = NULL;
    g_send_ctx[conn].npkts = 0;
    g_send_ctx[conn].acked = NULL;
    g_send_ctx[conn].send_mask = NULL;
    g_send_ctx[conn].peer_mask = 0;
    g_send_ctx[conn].ecn_pending = 0;
    g_send_ctx[conn].gap_us = 0;
    free(acked);
    free(send_mask);
    free(sent_at);
    /***********************
     * end of your code
     **********************/
    return (int)size;
}

/*------------- 可靠传输：接收端（待补全）-------------
 * 假设 size 是 PAYLOAD_LEN 的整数倍，故每个数据分组都是满载荷 PAYLOAD_LEN。
 * 当前实现里，可靠传输序号来自本地解析出的 seq_num，而不是论文头字段 count。 */
int m_recv(int conn, void *buf, uint32_t size, uint8_t op) {
    if (conn < 0 || conn >= g_conn_count) return -1;

    uint32_t npkts = size / PAYLOAD_LEN;
    if (npkts == 0) return 0;

    uint8_t *recvd = calloc(npkts, sizeof(uint8_t));
    uint32_t got = 0;
    uint64_t complete_at = 0;
    uint64_t last_progress = now_us();
    uint64_t last_fetch_at = 0;

    uint8_t *fetch_started = NULL;
    uint32_t *recv_mask = NULL;
    int32_t *local_sum = NULL;
    uint32_t remote_mask = 0;
    if (op == OP_ALLREDUCE) {
        fetch_started = calloc(npkts, sizeof(uint8_t));
        recv_mask = calloc(npkts, sizeof(uint32_t));
        local_sum = calloc(npkts * (PAYLOAD_LEN / sizeof(int32_t)), sizeof(int32_t));
        for (int r = 0; r < g_n; r++)
            if (r != g_rank) remote_mask |= (1u << r);
    }

    if (!recvd || (op == OP_ALLREDUCE && (!fetch_started || !recv_mask || !local_sum))) {
        free(recvd); free(fetch_started); free(recv_mask); free(local_sum);
        return -1;
    }

    while (1) {
        int saw_pkt = 0;
        for (int ci = 0; ci < g_conn_count; ci++) {
            rx_msg_t m;
            while (conn_pop(&g_conns[ci], &m)) {
                saw_pkt = 1;
                if (m.ecn)
                    mark_all_senders_ecn();
                if (m.is_ack == 1) {
                    send_ctx_t *sx = active_send_ctx();
                    if (sx && sx->send_mask && m.seq_num < sx->npkts && m.src_id < 32) {
                        sx->send_mask[m.seq_num] |= (1u << m.src_id);
                        if (sx->send_mask[m.seq_num] == sx->peer_mask)
                            sx->acked[m.seq_num] = 1;
                    }
                    continue;
                }

                if (m.is_fetch == 1 && m.payload_len == 0) {
                    if (g_local_src_buf && g_local_src_op == op && m.seq_num < g_local_src_npkts)
                        conn_send_ex(&g_conns[ci], m.seq_num, 0, op, 1, 1,
                                     g_local_src_buf + m.seq_num * PAYLOAD_LEN, PAYLOAD_LEN);
                    continue;
                }

                if (m.payload_len == 0 || m.seq_num >= npkts) continue;

                if (op == OP_ALLREDUCE && m.is_fetch == 1) {
                    if (!recvd[m.seq_num]) {
                        if (!fetch_started[m.seq_num]) {
                            memcpy(&local_sum[m.seq_num * (PAYLOAD_LEN / sizeof(int32_t))],
                                   g_local_src_buf + m.seq_num * PAYLOAD_LEN,
                                   PAYLOAD_LEN);
                            fetch_started[m.seq_num] = 1;
                        }
                        uint32_t bit = (m.src_id < 32) ? (1u << m.src_id) : 0;
                        if (bit != 0 && (recv_mask[m.seq_num] & bit) == 0) {
                            int32_t *dst_words = &local_sum[m.seq_num * (PAYLOAD_LEN / sizeof(int32_t))];
                            int32_t *src_words = (int32_t *)m.payload;
                            for (int i = 0; i < PAYLOAD_LEN / (int)sizeof(int32_t); i++)
                                dst_words[i] += src_words[i];
                            recv_mask[m.seq_num] |= bit;
                            if (recv_mask[m.seq_num] == remote_mask) {
                                memcpy((uint8_t *)buf + m.seq_num * PAYLOAD_LEN,
                                       dst_words, PAYLOAD_LEN);
                                recvd[m.seq_num] = 1;
                                got++;
                                last_progress = now_us();
                                send_ack_to_neighbors(m.seq_num, op);
                            }
                        }
                    }
                    continue;
                }

                if (!recvd[m.seq_num]) {
                    memcpy((uint8_t *)buf + m.seq_num * PAYLOAD_LEN,
                           m.payload, PAYLOAD_LEN);
                    if (op == OP_ALLREDUCE)
                        recv_mask[m.seq_num] = remote_mask;
                    recvd[m.seq_num] = 1;
                    got++;
                    last_progress = now_us();
                    if (op == OP_ALLREDUCE)
                        send_ack_to_neighbors(m.seq_num, op);
                }
                if (op != OP_ALLREDUCE) {
                    conn_send(&g_conns[ci], m.seq_num, 1, op, NULL, 0);
                }
            }
        }

        uint64_t now = now_us();
        if (op == OP_ALLREDUCE && got < npkts && now - last_progress >= RTO_US && now - last_fetch_at >= RTO_US) {
            uint32_t target = npkts;
            for (uint32_t s = 0; s < npkts; s++) {
                if (!recvd[s]) {
                    target = s;
                    break;
                }
            }
            if (target < npkts) {
                if (!fetch_started[target]) {
                    memcpy(&local_sum[target * (PAYLOAD_LEN / sizeof(int32_t))],
                           g_local_src_buf + target * PAYLOAD_LEN,
                           PAYLOAD_LEN);
                    fetch_started[target] = 1;
                }
                uint32_t missing = remote_mask & ~recv_mask[target];
                for (int r = 0; r < g_n; r++) {
                    if ((missing & (1u << r)) == 0) continue;
                    conn_t *peer = find_conn_by_remote(g_cfg[r].host_ip);
                    if (peer) {
                        conn_send_ex(peer, target, 0, op, 1, 0, NULL, 0);
                        break;
                    }
                }
                last_fetch_at = now;
            }
        }
        if (got >= npkts) {
            if (complete_at == 0) complete_at = now;
            else if (now - complete_at > 500000) break;
        }

        if (!saw_pkt) usleep(200);
    }

    free(recvd);
    free(fetch_started);
    free(recv_mask);
    free(local_sum);
    return (int)size;
}

/*------------- 通信 ------------- */
typedef struct {
    int      conn;
    char    *buf;
    uint32_t size;
    uint8_t  op;
} recv_args_t;

/* 接收线程入口（已给） */
static void *recv_worker(void *a) {
    recv_args_t *ra = (recv_args_t *)a;
    m_recv(ra->conn, ra->buf, ra->size, ra->op);
    return NULL;
}


/*======================================================================
 *  路由器端
 *====================================================================*/

static net_device_t  g_devs[MAX_GROUP_SIZE];
static int           g_dev_count = 0;
static dev_buffer_t  g_dev_buf;

static route_entry_t g_route[MAX_GROUP_SIZE];
static int           g_route_count = 0;

static conn_ctx_t    g_conn_ctx[MAX_GROUP_SIZE];
static int           g_group_n = 0;
static agtr_t       *g_agtr = NULL;

/* 路由器某端口抓包线程（已给） */
static void *dev_capture_thread(void *arg) {
    net_device_t *dev = (net_device_t *)arg;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;
    while ((rc = pcap_next_ex(dev->handle, &hdr, &pkt)) >= 0) {
        if (rc == 0) continue;
        pthread_mutex_lock(&g_dev_buf.lock);
        int nh = (g_dev_buf.head + 1) % DEV_RING_SIZE;
        if (nh != g_dev_buf.tail) {
            dev_pkt_t *e = &g_dev_buf.packets[g_dev_buf.head];
            e->device = dev;
            e->len = hdr->caplen > DEV_BUF_SIZE ? DEV_BUF_SIZE : hdr->caplen;
            memcpy(e->data, pkt, e->len);
            g_dev_buf.head = nh;
        } else {
            fprintf(stderr, "[router] packet buffer full, drop\n");
        }
        pthread_mutex_unlock(&g_dev_buf.lock);
    }
    return NULL;
}

/* 按目的 IP 查转发表，从对应端口注入该帧。已给。 */
static void router_forward(const uint8_t *frame, int len, uint32_t dst_ip) {
    const char *out_port = NULL;
    for (int i = 0; i < g_route_count; i++)
        if (g_route[i].dst_ip == dst_ip) { out_port = g_route[i].out_port; break; }
    if (!out_port) return;
    for (int i = 0; i < g_dev_count; i++)
        if (strcmp(g_devs[i].name, out_port) == 0) {
            pcap_inject(g_devs[i].handle, frame, len);
            return;
        }
}

/* 已给。 */
void init_router(config_entry_t *cfgs, int n) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_n = n;
    memcpy(g_cfg, cfgs, sizeof(config_entry_t) * n);
    memset(&g_dev_buf, 0, sizeof(g_dev_buf));
    pthread_mutex_init(&g_dev_buf.lock, NULL);

    for (int i = 0; i < n && g_dev_count < MAX_GROUP_SIZE; i++) {
        const char *port = cfgs[i].router_iface;
        int dup = 0;
        for (int k = 0; k < g_dev_count; k++)
            if (strcmp(g_devs[k].name, port) == 0) dup = 1;
        if (dup) continue;

        net_device_t *dev = &g_devs[g_dev_count];
        strncpy(dev->name, port, sizeof(dev->name) - 1);
        dev->index = g_dev_count;
        dev->handle = pcap_open_live(port, DEV_BUF_SIZE, 1, 1, errbuf);
        if (!dev->handle) {
            fprintf(stderr, "pcap_open_live(%s) failed: %s\n", port, errbuf);
            continue;
        }
        pcap_setdirection(dev->handle, PCAP_D_IN);
        pthread_create(&dev->thread_id, NULL, dev_capture_thread, dev);
        g_dev_count++;
    }

    for (int i = 0; i < n; i++) {
        g_route[g_route_count].dst_ip = cfgs[i].host_ip;
        strncpy(g_route[g_route_count].out_port, cfgs[i].router_iface,
                sizeof(g_route[g_route_count].out_port) - 1);
        g_route_count++;
    }

    g_group_n = n;
    for (int k = 0; k < n; k++) {
        g_conn_ctx[k].conn_id = (uint16_t)k;
        g_conn_ctx[k].src_ip  = cfgs[k].host_ip;
        g_conn_ctx[k].dst_ip  = cfgs[(k + 1) % n].host_ip;
        g_conn_ctx[k].rank    = k;
    }

    g_agtr = calloc(AGTR_ARRAY_SIZE, sizeof(agtr_t));   /* calloc 清零，初始各 slot 即干净 */
    if (!g_agtr) { fprintf(stderr, "agtr alloc failed\n"); exit(1); }
    printf("[router] opened %d ports, group_n=%d, agtr_slots=%d, window=%d\n",
           g_dev_count, g_group_n, AGTR_ARRAY_SIZE, WINDOW);
    fflush(stdout);
}

/* 从共享缓冲区取一帧（非阻塞）。已给。 */
static int dev_pop(dev_pkt_t *out) {
    int ok = 0;
    pthread_mutex_lock(&g_dev_buf.lock);
    if (g_dev_buf.tail != g_dev_buf.head) {
        *out = g_dev_buf.packets[g_dev_buf.tail];
        g_dev_buf.tail = (g_dev_buf.tail + 1) % DEV_RING_SIZE;
        ok = 1;
    }
    pthread_mutex_unlock(&g_dev_buf.lock);
    return ok;
}


static uint8_t router_ecn_mark(void) {
    uint8_t ecn = 0;
    pthread_mutex_lock(&g_dev_buf.lock);
    int used = g_dev_buf.head - g_dev_buf.tail;
    if (used < 0) used += DEV_RING_SIZE;
    if (used >= ECN_RING_THRESHOLD)
        ecn = 1;
    pthread_mutex_unlock(&g_dev_buf.lock);
    return ecn;
}

/* 把某个已聚合完成的 slot 广播给所有连接（取模寻址）。已给。 */
static void broadcast_slot(uint32_t seq) {
    agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    for (int dst_rank = 0; dst_rank < g_group_n; dst_rank++) {
        uint32_t dst_ip = g_cfg[dst_rank].host_ip;
        /* Aggregated result packets are sent directly by destination identity.
         * The src_ip is router-local metadata only; delivery depends on dst_ip. */
        int len = build_frame_ex(frame, 0, dst_ip,
                                 (uint32_t)dst_rank, (uint32_t)dst_rank,
                                 0, (uint16_t)(g_group_n > 0 ? g_group_n - 1 : 0),
                                 seq, 0, 0, 0,
                                 a->payload, PAYLOAD_LEN);
        ((mtp_header_t *)(frame + sizeof(eth_header_t) + sizeof(ip_header_t)))->ecn = router_ecn_mark();
        router_forward(frame, len, dst_ip);
    }
}

/* 聚合器复用：清空“一个窗口外”的 slot（gen 仅用于定位物理 slot）。已给。 */
static void clear_slot(uint32_t gen) {
    agtr_t *a = &g_agtr[gen % AGTR_ARRAY_SIZE];
    a->bitmap = 0;
    memset(a->payload, 0, sizeof(a->payload));
}


/*------------- 在网计算路由器：转发 + 聚合（待补全）------------- */
void INC(void) {
    printf("[router] running as INC (forward + aggregate)\n");
    fflush(stdout);
    uint32_t full_mask = (g_group_n >= 32) ? 0xffffffffu : ((1u << g_group_n) - 1);

    while (1) {
        dev_pkt_t pk;
        if (!dev_pop(&pk)) { usleep(200); continue; }

        /* 解析（已给） */
        eth_header_t *eth = (eth_header_t *)pk.data;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;
        ip_header_t *ip = (ip_header_t *)(pk.data + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        mtp_header_t *mtp = (mtp_header_t *)(pk.data + sizeof(eth_header_t) + ip_ihl);
        /* 载荷指针（数据分组载荷恒为 PAYLOAD_LEN）： */
        int32_t *payload = (int32_t *)(pk.data + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t));

        /***********************
         * start of your code
         *
         * Single-block simplified INC:
         *  1. ACK packets bypass aggregation and are forwarded directly.
         *  2. Data packets must belong to block 0.
         *  3. Contributor rank is derived from src_id (rank == vertex id in the simplified graph).
         *  4. count is expected to be g_group_n - 1 for the fully connected graph.
         *  5. One payload per rank is accumulated into the slot indexed by transport seq.
         **********************/
        if (mtp->is_ack == 1) {
            mtp->ecn = router_ecn_mark();
            router_forward(pk.data, pk.len, ip->dst_ip);
            continue;
        }
        if (mtp->is_fetch == 1) {
            /* Fetch packets bypass switch aggregation in the simplified model. */
            mtp->ecn = router_ecn_mark();
            router_forward(pk.data, pk.len, ip->dst_ip);
            continue;
        }
        if (ntohs(mtp->block_id) != 0) continue;

        uint32_t src_id = ntohl(mtp->src_id);
        uint32_t dst_id = ntohl(mtp->dst_id);
        uint32_t expected_count = ntohs(mtp->count);
        uint32_t seq = ntohs(ip->id);
        (void)dst_id;

        if (src_id >= (uint32_t)g_group_n) continue;
        if (expected_count != (uint32_t)(g_group_n - 1)) continue;

        uint16_t k = (uint16_t)src_id;
        agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
        uint32_t bit = 1u << k;

        if ((a->bitmap & bit) == 0) {
            for (int i = 0; i < PAYLOAD_LEN / (int)sizeof(int32_t); i++)
                a->payload[i] += payload[i];
            a->bitmap |= bit;
        } else if (mtp->resend == 1 && a->bitmap == full_mask) {
            /* Lost result/ACK: rebroadcast the completed aggregate without re-accumulating. */
            broadcast_slot(seq);
            continue;
        }

        if (a->bitmap != full_mask) continue;

        clear_slot(seq + WINDOW);
        broadcast_slot(seq);
        /***********************
         * end of your code
         **********************/
    }
}
