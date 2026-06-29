#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ECN_RING_THRESHOLD ((DEV_RING_SIZE * 3) / 4)

static config_entry_t g_cfg[MAX_GROUP_SIZE];
static int           g_n = 0;
static net_device_t  g_devs[MAX_GROUP_SIZE];
static int           g_dev_count = 0;
static dev_buffer_t  g_dev_buf;
static route_entry_t g_route[MAX_GROUP_SIZE];
static int           g_route_count = 0;
static conn_ctx_t    g_conn_ctx[MAX_GROUP_SIZE];
static int           g_group_n = 0;
static agtr_t       *g_agtr = NULL;
static int           g_drop_result_dst = -1;
static int           g_drop_result_seq = -1;
static int           g_drop_result_done = 0;
static uint16_t      g_current_block = 0;
static uint32_t      g_block_done_bitmap = 0;

static void init_fetch_test_fault(void) {
    const char *spec = getenv("FETCH_TEST_DROP_RESULT");
    int dst = -1;
    int seq = -1;
    if (!spec) return;
    if (sscanf(spec, "%d:%d", &dst, &seq) == 2 && dst >= 0 && seq >= 0) {
        g_drop_result_dst = dst;
        g_drop_result_seq = seq;
        g_drop_result_done = 0;
    }
}

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

static void broadcast_block_release(uint16_t next_block_id) {
    uint8_t frame[HDR_LEN];
    for (int dst_rank = 0; dst_rank < g_group_n; dst_rank++) {
        uint32_t dst_ip = g_cfg[dst_rank].host_ip;
        int len = build_frame_ex(frame, 0, dst_ip,
                                 0, (uint32_t)dst_rank,
                                 next_block_id, 0, 0,
                                 1, 1, 0, NULL, 0);
        router_forward(frame, len, dst_ip);
    }
}

void init_router(config_entry_t *cfgs, int n) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_n = n;
    memcpy(g_cfg, cfgs, sizeof(config_entry_t) * n);
    memset(&g_dev_buf, 0, sizeof(g_dev_buf));
    pthread_mutex_init(&g_dev_buf.lock, NULL);
    common_set_group(cfgs, n);
    init_fetch_test_fault();
    g_current_block = 0;
    g_block_done_bitmap = 0;

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

    g_agtr = calloc(AGTR_ARRAY_SIZE, sizeof(agtr_t));
    if (!g_agtr) { fprintf(stderr, "agtr alloc failed\n"); exit(1); }
    printf("[router] opened %d ports, group_n=%d, agtr_slots=%d, window=%d, block_npkts=%d\n",
           g_dev_count, g_group_n, AGTR_ARRAY_SIZE, WINDOW, BLOCK_NPKTS);
    fflush(stdout);
}

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

static void broadcast_slot(uint32_t seq) {
    agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    uint16_t block_id = block_id_of_seq(seq);
    for (int dst_rank = 0; dst_rank < g_group_n; dst_rank++) {
        uint32_t dst_ip = g_cfg[dst_rank].host_ip;
        if (!g_drop_result_done && g_drop_result_dst == dst_rank && g_drop_result_seq == (int)seq) {
            g_drop_result_done = 1;
            continue;
        }
        int len = build_frame_ex(frame, 0, dst_ip,
                                 (uint32_t)dst_rank, (uint32_t)dst_rank,
                                 block_id, (uint16_t)count_bits32(neighbor_mask_of((uint32_t)dst_rank)),
                                 seq, 0, 0, 0,
                                 a->payload, PAYLOAD_LEN);
        ((mtp_header_t *)(frame + sizeof(eth_header_t) + sizeof(ip_header_t)))->ecn = router_ecn_mark();
        router_forward(frame, len, dst_ip);
    }
}

static void clear_slot(uint32_t gen) {
    agtr_t *a = &g_agtr[gen % AGTR_ARRAY_SIZE];
    a->bitmap = 0;
    memset(a->payload, 0, sizeof(a->payload));
}

void INC(void) {
    printf("[router] running as INC (forward + aggregate)\n");
    fflush(stdout);
    uint32_t full_mask = (g_group_n >= 32) ? 0xffffffffu : ((1u << g_group_n) - 1);

    while (1) {
        dev_pkt_t pk;
        if (!dev_pop(&pk)) { usleep(200); continue; }

        eth_header_t *eth = (eth_header_t *)pk.data;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;
        ip_header_t *ip = (ip_header_t *)(pk.data + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        mtp_header_t *mtp = (mtp_header_t *)(pk.data + sizeof(eth_header_t) + ip_ihl);
        int32_t *payload = (int32_t *)(pk.data + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t));
        uint16_t block_id = ntohs(mtp->block_id);

        if (mtp->is_ack == 1 && mtp->is_fetch == 1) {
            uint32_t src_id = ntohl(mtp->src_id);
            if (ip->src_ip != 0 && block_id == g_current_block && src_id < 32) {
                g_block_done_bitmap |= (1u << src_id);
                if (g_block_done_bitmap == full_mask) {
                    g_current_block++;
                    g_block_done_bitmap = 0;
                    broadcast_block_release(g_current_block);
                }
            }
            continue;
        }
        if (mtp->is_ack == 1) {
            mtp->ecn = router_ecn_mark();
            router_forward(pk.data, pk.len, ip->dst_ip);
            continue;
        }
        if (mtp->is_fetch == 1) {
            if (ntohs(ip->total_len) > (uint16_t)(ip_ihl + sizeof(mtp_header_t)))
                clear_slot(ntohs(ip->id));
            mtp->ecn = router_ecn_mark();
            router_forward(pk.data, pk.len, ip->dst_ip);
            continue;
        }
        if (block_id != g_current_block) continue;

        uint32_t src_id = ntohl(mtp->src_id);
        uint32_t dst_id = ntohl(mtp->dst_id);
        uint32_t expected_count = ntohs(mtp->count);
        uint32_t seq = ntohs(ip->id);
        uint32_t required_count;
        (void)dst_id;

        if (src_id >= (uint32_t)g_group_n) continue;
        required_count = (uint32_t)count_bits32(neighbor_mask_of(src_id));
        if (expected_count != required_count) continue;

        uint16_t k = (uint16_t)src_id;
        agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
        uint32_t bit = 1u << k;

        if ((a->bitmap & bit) == 0) {
            for (int i = 0; i < PAYLOAD_LEN / (int)sizeof(int32_t); i++)
                a->payload[i] += payload[i];
            a->bitmap |= bit;
        } else if (mtp->resend == 1 && a->bitmap == full_mask) {
            broadcast_slot(seq);
            continue;
        }

        if (a->bitmap != full_mask) continue;

        clear_slot(seq + WINDOW);
        broadcast_slot(seq);
    }
}
