#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

static int g_n = 0;
static config_entry_t g_cfg[MAX_GROUP_SIZE];
static uint32_t g_neighbor_masks[MAX_GROUP_SIZE];

uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

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

int build_frame_ex(uint8_t *buf,
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

static uint32_t default_neighbor_mask(int rank) {
    uint32_t mask = 0;
    for (int r = 0; r < g_n; r++)
        if (r != rank) mask |= (1u << r);
    return mask;
}

int count_bits32(uint32_t x) {
    int n = 0;
    while (x) {
        x &= (x - 1);
        n++;
    }
    return n;
}

int rank_of_ip(uint32_t ip) {
    for (int i = 0; i < g_n; i++)
        if (g_cfg[i].host_ip == ip) return g_cfg[i].rank;
    return -1;
}

uint32_t neighbor_mask_of(uint32_t vertex_id) {
    if (vertex_id >= (uint32_t)g_n) return 0;
    return g_neighbor_masks[vertex_id];
}

uint16_t block_id_of_seq(uint32_t seq) {
    return (uint16_t)(seq / BLOCK_NPKTS);
}

uint32_t block_start_seq(uint16_t block_id) {
    return (uint32_t)block_id * BLOCK_NPKTS;
}

uint32_t block_end_seq(uint16_t block_id, uint32_t total_npkts) {
    uint32_t end = block_start_seq(block_id) + BLOCK_NPKTS;
    return end > total_npkts ? total_npkts : end;
}

uint16_t total_blocks_for_npkts(uint32_t total_npkts) {
    return (uint16_t)((total_npkts + BLOCK_NPKTS - 1) / BLOCK_NPKTS);
}

static void init_default_neighbor_masks(void) {
    for (int r = 0; r < g_n; r++)
        g_neighbor_masks[r] = default_neighbor_mask(r);
}

static void try_load_neighbor_masks(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *save = NULL;
        char *tok = strtok_r(line, ", \t\r\n", &save);
        if (!tok) continue;
        int vertex = atoi(tok);
        if (vertex < 0 || vertex >= g_n) continue;

        uint32_t mask = 0;
        while ((tok = strtok_r(NULL, ", \t\r\n", &save)) != NULL) {
            int nbr = atoi(tok);
            if (nbr >= 0 && nbr < g_n && nbr != vertex)
                mask |= (1u << nbr);
        }
        g_neighbor_masks[vertex] = mask;
    }
    fclose(fp);
}

void common_set_group(config_entry_t *cfgs, int n) {
    g_n = n;
    memcpy(g_cfg, cfgs, sizeof(config_entry_t) * n);
    init_default_neighbor_masks();
    try_load_neighbor_masks("graph.cfg");
}
