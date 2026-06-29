#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>

#define PAYLOAD_LEN   1024
#define IP_PROTO_MTP  253
#define ETH_TYPE_IP   0x0800

#define MAX_GROUP_SIZE 8
#define MAX_CONNS      8

#define WINDOW        32
#define RTO_US        50000
#define AGTR_ARRAY_SIZE (2 * WINDOW)

#define OP_TRANSMISSION 1
#define OP_ALLREDUCE    2

#define FLAG_FALSE      0
#define FLAG_TRUE       1

typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
} __attribute__((packed)) eth_header_t;

typedef struct {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed)) ip_header_t;

typedef struct {
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t block_id;
    uint16_t count;
    uint8_t  is_ack;
    uint8_t  is_fetch;
    uint8_t  ecn;
    uint8_t  resend;
} __attribute__((packed)) mtp_header_t;

#define HDR_LEN (sizeof(eth_header_t) + sizeof(ip_header_t) + sizeof(mtp_header_t))

typedef struct {
    int      rank;
    char     host_name[32];
    char     host_iface[32];
    char     router_iface[32];
    uint32_t host_ip;
} config_entry_t;

typedef struct {
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t block_id;
    uint16_t count;
    uint32_t seq_num;
    uint16_t payload_len;
    uint8_t  is_ack;
    uint8_t  is_fetch;
    uint8_t  ecn;
    uint8_t  resend;
    uint8_t  payload[PAYLOAD_LEN];
} rx_msg_t;

#define RXQ_SIZE 4096
typedef struct {
    int             in_use;
    uint16_t        conn_id;
    uint32_t        local_ip;
    uint32_t        remote_ip;
    rx_msg_t        queue[RXQ_SIZE];
    volatile int    head;
    volatile int    tail;
    pthread_mutex_t lock;
} conn_t;

typedef struct {
    char      name[32];
    pcap_t   *handle;
    pthread_t thread_id;
    int       index;
} net_device_t;

#define DEV_BUF_SIZE 4096
typedef struct {
    net_device_t *device;
    uint8_t       data[DEV_BUF_SIZE];
    uint32_t      len;
} dev_pkt_t;

#define DEV_RING_SIZE 65536
typedef struct {
    dev_pkt_t       packets[DEV_RING_SIZE];
    volatile int    head;
    volatile int    tail;
    pthread_mutex_t lock;
} dev_buffer_t;

typedef struct {
    uint32_t dst_ip;
    char     out_port[32];
} route_entry_t;

typedef struct {
    uint16_t conn_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    int      rank;
} conn_ctx_t;

typedef struct {
    uint32_t bitmap;
    int32_t  payload[PAYLOAD_LEN / sizeof(int32_t)];
} agtr_t;

void common_set_group(config_entry_t *cfgs, int n);
int rank_of_ip(uint32_t ip);
int count_bits32(uint32_t x);
uint32_t neighbor_mask_of(uint32_t vertex_id);
int build_frame_ex(uint8_t *buf,
                   uint32_t src_ip, uint32_t dst_ip,
                   uint32_t src_id, uint32_t dst_id,
                   uint16_t block_id, uint16_t count,
                   uint32_t seq_for_transport,
                   uint8_t is_ack, uint8_t is_fetch, uint8_t resend,
                   const void *payload, uint16_t plen);

void init_host(config_entry_t *cfgs, int n, const char *host_name);
int  init_conn(uint16_t conn_id, uint32_t local_ip, uint32_t remote_ip);
int  m_send(int conn, const void *buf, uint32_t size, uint8_t op);
int  m_recv(int conn, void *buf, uint32_t size, uint8_t op);
void register_local_source(const void *buf, uint32_t size, uint8_t op);
void clear_local_source(void);

void init_router(config_entry_t *cfgs, int n);
void INC(void);

uint64_t now_us(void);

#endif
