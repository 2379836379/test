#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

/*======================================================================
 *  实验七入口程序（简化版）
 *
 *  仅保留在网聚合功能：
 *    - router 端运行 INC()
 *    - host 端上传本地顶点特征，并接收交换机聚合结果
 *
 *  用法：./inc <name> <config> allreduce
 *====================================================================*/

#define MSG_SIZE (1024 * 1024)

static config_entry_t cfgs[MAX_GROUP_SIZE];
static int n = 0;

typedef struct {
    int conn;
    const void *buf;
    uint32_t size;
    uint8_t op;
} send_args_t;

static void *send_worker(void *arg) {
    send_args_t *sa = (send_args_t *)arg;
    m_send(sa->conn, sa->buf, sa->size, sa->op);
    return NULL;
}

static int load_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) { perror("open config"); return -1; }
    char line[256];
    while (fgets(line, sizeof(line), fp) && n < MAX_GROUP_SIZE) {
        if (line[0] == '#' || line[0] == '\n') continue;
        config_entry_t *e = &cfgs[n];
        char ip[32];
        if (sscanf(line, "%d,%31[^,],%31[^,],%31[^,],%31s",
                   &e->rank, e->host_name, e->host_iface, e->router_iface, ip) != 5) {
            fprintf(stderr, "bad config line: %s", line);
            continue;
        }
        if (inet_pton(AF_INET, ip, &e->host_ip) != 1) {
            fprintf(stderr, "bad ip: %s\n", ip);
            continue;
        }
        n++;
    }
    fclose(fp);
    return n;
}

static uint32_t ip_of_rank(int r) {
    for (int i = 0; i < n; i++) if (cfgs[i].rank == r) return cfgs[i].host_ip;
    return 0;
}

static int my_rank_of(const char *name) {
    for (int i = 0; i < n; i++) if (strcmp(cfgs[i].host_name, name) == 0) return cfgs[i].rank;
    return -1;
}

static void read_input(int rank, int32_t *buf, uint32_t maxints) {
    char fn[64];
    snprintf(fn, sizeof(fn), "input-%d.data", rank);
    FILE *fp = fopen(fn, "r");
    if (!fp) { perror(fn); exit(1); }
    uint32_t c = 0; long v;
    while (c < maxints && fscanf(fp, "%ld", &v) == 1) buf[c++] = (int32_t)v;
    for (; c < maxints; c++) buf[c] = 0;
    fclose(fp);
}

static void write_output(int rank, const int32_t *buf, uint32_t nints) {
    char fn[64];
    snprintf(fn, sizeof(fn), "output-%d.data", rank);
    FILE *fp = fopen(fn, "w");
    if (!fp) { perror(fn); return; }
    for (uint32_t i = 0; i < nints; i++) fprintf(fp, "%d\n", buf[i]);
    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <name> <config> allreduce\n", argv[0]);
        return 1;
    }
    const char *name = argv[1];
    const char *cfg  = argv[2];
    const char *mode = argv[3];

    if (strcmp(mode, "allreduce") != 0) {
        fprintf(stderr, "only allreduce mode is supported\n");
        return 1;
    }
    if (load_config(cfg) <= 0) {
        fprintf(stderr, "no config\n");
        return 1;
    }

    if (strcmp(name, "router") == 0) {
        init_router(cfgs, n);
        INC();
        return 0;
    }

    init_host(cfgs, n, name);
    int rank = my_rank_of(name);
    if (rank < 0) {
        fprintf(stderr, "unknown host %s\n", name);
        return 1;
    }

    uint32_t nints = MSG_SIZE / sizeof(int32_t);
    int32_t *src = malloc(MSG_SIZE);
    int32_t *dst = calloc(1, MSG_SIZE);
    if (!src || !dst) {
        fprintf(stderr, "alloc failed\n");
        free(src);
        free(dst);
        return 1;
    }
    read_input(rank, src, nints);

    int succ = (rank + 1) % n;

    int send_conn = init_conn((uint16_t)rank, ip_of_rank(rank), ip_of_rank(succ));
    if (send_conn < 0) {
        fprintf(stderr, "init_conn failed\n");
        free(src);
        free(dst);
        return 1;
    }
    for (int r = 0; r < n; r++) {
        if (r == rank || r == succ) continue;
        if (init_conn((uint16_t)r, ip_of_rank(rank), ip_of_rank(r)) < 0) {
            fprintf(stderr, "init_conn failed\n");
            free(src);
            free(dst);
            return 1;
        }
    }
    int recv_conn = init_conn(0xffffu, ip_of_rank(rank), 0);
    if (recv_conn < 0) {
        fprintf(stderr, "init_conn failed\n");
        free(src);
        free(dst);
        return 1;
    }

    register_local_source(src, MSG_SIZE, OP_ALLREDUCE);

    send_args_t sa = {
        .conn = send_conn,
        .buf = src,
        .size = MSG_SIZE,
        .op = OP_ALLREDUCE,
    };
    pthread_t send_tid;
    pthread_create(&send_tid, NULL, send_worker, &sa);

    m_recv(recv_conn, dst, MSG_SIZE, OP_ALLREDUCE);
    pthread_join(send_tid, NULL);

    write_output(rank, dst, nints);
    printf("[host] rank%d allreduce done\n", rank);
    fflush(stdout);

    clear_local_source();
    free(src);
    free(dst);
    return 0;
}
