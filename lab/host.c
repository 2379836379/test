#include "common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CC_GAP_STEP_US 5
#define CC_GAP_MAX_US 2000

static config_entry_t g_cfg[MAX_GROUP_SIZE];
static int            g_n = 0;
static int            g_rank = -1;
static uint32_t       g_my_ip = 0;
static pcap_t        *g_host_handle = NULL;
static pthread_mutex_t g_tx_lock = PTHREAD_MUTEX_INITIALIZER;
static conn_t         g_conns[MAX_CONNS];
static int            g_conn_count = 0;

typedef struct {
    int active;
    const uint8_t *buf;
    uint32_t npkts;
    uint8_t op;
    uint8_t *seq_acked;
    uint32_t neighbor_ack_bitmap;
    uint32_t neighbor_mask;
    uint32_t vertex_id;
    uint16_t block_id;
    volatile uint8_t ecn_pending;
    uint32_t gap_us;
} send_vertex_state_t;

typedef struct {
    int active;
    uint32_t vertex_id;
    uint16_t block_id;
    uint32_t neighbor_recv_bitmap;
    uint32_t neighbor_mask;
    uint8_t switch_result_seen;
} recv_vertex_state_t;

static send_vertex_state_t g_send_states[MAX_GROUP_SIZE];
static recv_vertex_state_t g_recv_states[MAX_GROUP_SIZE];
static const uint8_t *g_local_src_buf = NULL;
static uint32_t g_local_src_npkts = 0;
static uint8_t g_local_src_op = 0;

static void conn_send(conn_t *cn, uint32_t seq, uint8_t ack_flag, uint8_t op,
                      const void *payload, uint16_t plen);
static void host_inject(uint8_t *frame, int len);

static send_vertex_state_t *send_state_of(uint32_t vertex_id) {
    if (vertex_id >= MAX_GROUP_SIZE) return NULL;
    return &g_send_states[vertex_id];
}

static recv_vertex_state_t *recv_state_of(uint32_t vertex_id) {
    if (vertex_id >= MAX_GROUP_SIZE) return NULL;
    return &g_recv_states[vertex_id];
}

static conn_t *find_conn_by_remote(uint32_t remote_ip) {
    for (int i = 0; i < g_conn_count; i++) {
        if (!g_conns[i].in_use) continue;
        if (g_conns[i].local_ip == g_my_ip && g_conns[i].remote_ip == remote_ip)
            return &g_conns[i];
    }
    return NULL;
}

static void mark_sender_ecn(uint32_t vertex_id) {
    send_vertex_state_t *sv = send_state_of(vertex_id);
    if (sv && sv->active)
        sv->ecn_pending = 1;
}

static void send_ack_to_neighbors(uint32_t vertex_id, uint16_t block_id, uint8_t op) {
    (void)op;
    uint32_t nbr_mask = neighbor_mask_of(vertex_id);
    for (int r = 0; r < g_n; r++) {
        if ((nbr_mask & (1u << r)) == 0) continue;
        conn_t *peer = find_conn_by_remote(g_cfg[r].host_ip);
        if (!peer) continue;

        uint8_t frame[HDR_LEN];
        int len = build_frame_ex(frame, peer->local_ip, peer->remote_ip,
                                 (uint32_t)g_rank, (uint32_t)r,
                                 block_id, 0, 0,
                                 1, 0, 0, NULL, 0);
        host_inject(frame, len);
    }
}

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

static void host_inject(uint8_t *frame, int len) {
    pthread_mutex_lock(&g_tx_lock);
    pcap_inject(g_host_handle, frame, len);
    pthread_mutex_unlock(&g_tx_lock);
}

static void conn_send_ex(conn_t *cn, uint32_t seq, uint8_t ack_flag, uint8_t op,
                         uint8_t is_fetch, uint8_t resend,
                         const void *payload, uint16_t plen) {
    (void)op;
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    int src_rank = rank_of_ip(cn->local_ip);
    int dst_rank = rank_of_ip(cn->remote_ip);
    uint16_t count = 0;
    if (!ack_flag && src_rank >= 0)
        count = (uint16_t)count_bits32(neighbor_mask_of((uint32_t)src_rank));
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

static void *host_rx_thread(void *arg) {
    (void)arg;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;
    while ((rc = pcap_next_ex(g_host_handle, &hdr, &pkt)) >= 0) {
        if (rc == 0) continue;
        if (hdr->caplen < HDR_LEN) continue;
        const eth_header_t *eth = (const eth_header_t *)pkt;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;
        const ip_header_t *ip = (const ip_header_t *)(pkt + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;
        if (ip->src_ip == g_my_ip) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        const mtp_header_t *mtp =
            (const mtp_header_t *)(pkt + sizeof(eth_header_t) + ip_ihl);
        int plen = ntohs(ip->total_len) - ip_ihl - (int)sizeof(mtp_header_t);
        if (plen < 0) plen = 0;
        if (plen > PAYLOAD_LEN) plen = PAYLOAD_LEN;

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

        pthread_mutex_lock(&cn->lock);
        int nh = (cn->head + 1) % RXQ_SIZE;
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
            if (plen > 0)
                memcpy(m->payload, pkt + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t), plen);
            cn->head = nh;
        }
        pthread_mutex_unlock(&cn->lock);
    }
    return NULL;
}

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

void init_host(config_entry_t *cfgs, int n, const char *host_name) {
    g_n = n;
    memcpy(g_cfg, cfgs, sizeof(config_entry_t) * n);
    common_set_group(cfgs, n);

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

int m_send(int conn, const void *buf, uint32_t size, uint8_t op) {
    if (conn < 0 || conn >= g_conn_count) return -1;
    conn_t *cn = &g_conns[conn];
    uint32_t npkts = size / PAYLOAD_LEN;
    if (npkts == 0) return 0;

    uint8_t *acked = calloc(npkts, sizeof(uint8_t));
    uint64_t *sent_at = calloc(npkts, sizeof(uint64_t));
    uint32_t base = 0;
    uint32_t peer_mask = neighbor_mask_of((uint32_t)g_rank);

    if (!acked || !sent_at) {
        free(acked);
        free(sent_at);
        return -1;
    }

    send_vertex_state_t *sv = send_state_of((uint32_t)g_rank);
    if (!sv) {
        free(acked);
        free(sent_at);
        return -1;
    }
    memset(sv, 0, sizeof(*sv));
    sv->active = 1;
    sv->buf = (const uint8_t *)buf;
    sv->npkts = npkts;
    sv->op = op;
    sv->seq_acked = acked;
    sv->neighbor_ack_bitmap = 0;
    sv->neighbor_mask = peer_mask;
    sv->vertex_id = (uint32_t)g_rank;
    sv->block_id = 0;
    sv->ecn_pending = 0;
    sv->gap_us = 100;

    uint64_t last_gap_adjust = now_us();
    uint64_t last_tx_at = 0;

    while (base < npkts || sv->neighbor_ack_bitmap != sv->neighbor_mask) {
        uint64_t now = now_us();
        if (sv->ecn_pending) {
            uint32_t gap = sv->gap_us;
            sv->gap_us = gap == 0 ? 1 : (gap * 2 > CC_GAP_MAX_US ? CC_GAP_MAX_US : gap * 2);
            sv->ecn_pending = 0;
            last_gap_adjust = now;
        } else if (sv->gap_us > 0 && now - last_gap_adjust >= RTO_US) {
            sv->gap_us = (sv->gap_us > CC_GAP_STEP_US) ?
                         (sv->gap_us - CC_GAP_STEP_US) : 0;
            last_gap_adjust = now;
        }
        while (base < npkts && acked[base]) base++;
        uint32_t end = base + WINDOW;
        if (end > npkts) end = npkts;
        for (uint32_t s = base; s < end; s++) {
            uint64_t send_now = now_us();
            if (sv->gap_us > 0 && last_tx_at != 0 && send_now - last_tx_at < sv->gap_us)
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

    memset(sv, 0, sizeof(*sv));
    free(acked);
    free(sent_at);
    return (int)size;
}

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
    uint32_t *pull_mask = NULL;
    uint64_t *fetch_sent_at = NULL;
    uint32_t *neighbor_cached_pkts = NULL;
    int32_t *local_sum = NULL;
    uint8_t *feature_cached = NULL;
    int32_t *feature_cache = NULL;
    uint32_t remote_mask = 0;
    recv_vertex_state_t *rv = NULL;
    uint8_t ack_sent = 0;
    int words_per_pkt = PAYLOAD_LEN / (int)sizeof(int32_t);
    if (op == OP_ALLREDUCE) {
        fetch_started = calloc(npkts, sizeof(uint8_t));
        pull_mask = calloc(npkts, sizeof(uint32_t));
        fetch_sent_at = calloc(npkts, sizeof(uint64_t));
        neighbor_cached_pkts = calloc(MAX_GROUP_SIZE, sizeof(uint32_t));
        local_sum = calloc(npkts * words_per_pkt, sizeof(int32_t));
        feature_cached = calloc((size_t)MAX_GROUP_SIZE * npkts, sizeof(uint8_t));
        feature_cache = calloc((size_t)MAX_GROUP_SIZE * npkts * words_per_pkt, sizeof(int32_t));
        remote_mask = neighbor_mask_of((uint32_t)g_rank);
        rv = recv_state_of((uint32_t)g_rank);
        if (rv) {
            memset(rv, 0, sizeof(*rv));
            rv->active = 1;
            rv->vertex_id = (uint32_t)g_rank;
            rv->block_id = 0;
            rv->neighbor_mask = remote_mask;
            rv->neighbor_recv_bitmap = 0;
            rv->switch_result_seen = 0;
        }
    }

    if (!recvd || (op == OP_ALLREDUCE && (!fetch_started || !pull_mask || !fetch_sent_at || !neighbor_cached_pkts || !local_sum || !feature_cached || !feature_cache || !rv))) {
        free(recvd); free(fetch_started); free(pull_mask); free(fetch_sent_at); free(neighbor_cached_pkts); free(local_sum); free(feature_cached); free(feature_cache);
        return -1;
    }

    while (1) {
        int saw_pkt = 0;
        for (int ci = 0; ci < g_conn_count; ci++) {
            rx_msg_t m;
            while (conn_pop(&g_conns[ci], &m)) {
                saw_pkt = 1;
                if (m.ecn)
                    mark_sender_ecn(m.dst_id);
                if (m.is_ack == 1) {
                    send_vertex_state_t *sv = send_state_of(m.dst_id);
                    if (sv && sv->active &&
                        m.block_id == sv->block_id &&
                        m.src_id < 32) {
                        sv->neighbor_ack_bitmap |= (1u << m.src_id);
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

                conn_t *src_cn = &g_conns[ci];
                int is_complete_result = (src_cn->remote_ip == 0 && m.is_fetch == 0);
                int is_non_aggregated_feature = (op == OP_ALLREDUCE && m.is_fetch == 1 && src_cn->remote_ip != 0);

                if (is_complete_result) {
                    send_vertex_state_t *sv = send_state_of(m.dst_id);
                    if (sv && sv->active && m.seq_num < sv->npkts)
                        sv->seq_acked[m.seq_num] = 1;
                }

                if (is_non_aggregated_feature) {
                    size_t cache_slot = (size_t)m.src_id * npkts + m.seq_num;
                    if (m.src_id < MAX_GROUP_SIZE && !feature_cached[cache_slot]) {
                        memcpy(&feature_cache[cache_slot * words_per_pkt], m.payload, PAYLOAD_LEN);
                        feature_cached[cache_slot] = 1;
                        neighbor_cached_pkts[m.src_id]++;
                        if (rv && neighbor_cached_pkts[m.src_id] == npkts && m.src_id < 32)
                            rv->neighbor_recv_bitmap |= (1u << m.src_id);
                    }
                    if (!recvd[m.seq_num]) {
                        if (!fetch_started[m.seq_num]) {
                            memcpy(&local_sum[m.seq_num * words_per_pkt],
                                   g_local_src_buf + m.seq_num * PAYLOAD_LEN,
                                   PAYLOAD_LEN);
                            fetch_started[m.seq_num] = 1;
                        }
                        uint32_t bit = (m.src_id < 32) ? (1u << m.src_id) : 0;
                        if (bit != 0 && (pull_mask[m.seq_num] & bit) == 0) {
                            int32_t *dst_words = &local_sum[m.seq_num * words_per_pkt];
                            int32_t *src_words = &feature_cache[cache_slot * words_per_pkt];
                            for (int i = 0; i < words_per_pkt; i++)
                                dst_words[i] += src_words[i];
                            pull_mask[m.seq_num] |= bit;
                            if (pull_mask[m.seq_num] == remote_mask) {
                                memcpy((uint8_t *)buf + m.seq_num * PAYLOAD_LEN,
                                       dst_words, PAYLOAD_LEN);
                                recvd[m.seq_num] = 1;
                                got++;
                                last_progress = now_us();
                            }
                        }
                    }
                    continue;
                }

                if (!recvd[m.seq_num]) {
                    memcpy((uint8_t *)buf + m.seq_num * PAYLOAD_LEN,
                           m.payload, PAYLOAD_LEN);
                    recvd[m.seq_num] = 1;
                    got++;
                    last_progress = now_us();
                }
                if (op == OP_ALLREDUCE && is_complete_result) {
                    if (rv && m.dst_id == rv->vertex_id && m.block_id == rv->block_id)
                        rv->switch_result_seen = 1;
                } else if (op != OP_ALLREDUCE) {
                    conn_send(&g_conns[ci], m.seq_num, 1, op, NULL, 0);
                }
            }
        }

        uint64_t now = now_us();
        if (op == OP_ALLREDUCE && got < npkts && rv && !rv->switch_result_seen &&
            now - last_progress >= RTO_US && now - last_fetch_at >= RTO_US) {
            uint32_t missing_neighbors = rv->neighbor_mask & ~rv->neighbor_recv_bitmap;
            for (int r = 0; r < g_n; r++) {
                if ((missing_neighbors & (1u << r)) == 0) continue;
                conn_t *peer = find_conn_by_remote(g_cfg[r].host_ip);
                if (!peer) continue;
                for (uint32_t s = 0; s < npkts; s++) {
                    size_t cache_slot = (size_t)r * npkts + s;
                    if (recvd[s]) continue;
                    if (feature_cached[cache_slot]) continue;
                    if (fetch_sent_at[s] != 0 && now - fetch_sent_at[s] < RTO_US) continue;
                    conn_send_ex(peer, s, 0, op, 1, 1, NULL, 0);
                    fetch_sent_at[s] = now;
                }
            }
            last_fetch_at = now;
        }
        if (op == OP_ALLREDUCE && got >= npkts && rv && !ack_sent) {
            rv->neighbor_recv_bitmap = rv->neighbor_mask;
            send_ack_to_neighbors((uint32_t)g_rank, 0, op);
            ack_sent = 1;
        }
        if (got >= npkts) {
            if (complete_at == 0) complete_at = now;
            else if (now - complete_at > 500000) break;
        }

        if (!saw_pkt) usleep(200);
    }

    if (rv)
        memset(rv, 0, sizeof(*rv));
    free(recvd);
    free(fetch_started);
    free(pull_mask);
    free(fetch_sent_at);
    free(neighbor_cached_pkts);
    free(local_sum);
    free(feature_cached);
    free(feature_cache);
    return (int)size;
}
