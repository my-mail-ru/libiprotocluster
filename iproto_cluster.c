#include "iproto_private.h"

#include <stdlib.h>
#include <string.h>

struct iproto_cluster {
    struct {
        iproto_shard_t **a;
        int n;
    } shards;
    iproto_cluster_opts_t opts;
    iproto_stat_t *stat;
};

static int cluster_count = 0;

iproto_cluster_t *iproto_cluster_init(void) {
    iproto_initialize();
    iproto_cluster_t *cluster = malloc(sizeof(*cluster));
    memset(cluster, 0, sizeof(*cluster));
    cluster->opts.connect_timeout.tv_usec = 200000;
    cluster->opts.server_freeze.tv_sec = 15;
    if (cluster_count++ == 0)
        iproto_init_globals();
    return cluster;
}

void iproto_cluster_free(iproto_cluster_t *cluster) {
    for (int i = 0; i < cluster->shards.n; i++) {
        iproto_shard_free(cluster->shards.a[i]);
    }
    if (--cluster_count == 0)
        iproto_free_globals();
    free(cluster->shards.a);
    free(cluster);
}

iproto_cluster_opts_t *iproto_cluster_options(iproto_cluster_t *cluster) {
    return &cluster->opts;
}

void iproto_cluster_add_shard(iproto_cluster_t *cluster, iproto_shard_t *shard) {
    cluster->shards.a = realloc(cluster->shards.a, ++cluster->shards.n * sizeof(iproto_shard_t *));
    cluster->shards.a[cluster->shards.n - 1] = shard;
}

int iproto_cluster_get_shard_count(iproto_cluster_t *cluster) {
    return cluster->shards.n;
}

static iproto_shard_t *iproto_cluster_get_shard(iproto_cluster_t *cluster, iproto_message_t *message) {
    unsigned shard_num = iproto_message_options(message)->shard_num;
    if (shard_num == 0 && cluster->shards.n == 1) {
        shard_num = 1;
    } else if (shard_num < 1 || shard_num > cluster->shards.n) {
        iproto_message_set_response(message, NULL, ERR_CODE_INVALID_SHARD_NUM, NULL, 0);
        return NULL;
    }
    return cluster->shards.a[shard_num - 1];
}

iproto_server_t *iproto_cluster_get_server(iproto_cluster_t *cluster, iproto_message_t *message, iproto_server_t **not_servers, int n_not_servers) {
    iproto_shard_t *shard = iproto_cluster_get_shard(cluster, message);
    if (!shard) return NULL;
    return iproto_shard_get_server(shard, message, not_servers, n_not_servers, &cluster->opts.server_freeze);
}

bool iproto_cluster_is_server_replica(iproto_cluster_t *cluster, iproto_message_t *message, iproto_server_t *server) {
    iproto_shard_t *shard = iproto_cluster_get_shard(cluster, message);
    if (!shard) return false;
    return iproto_shard_is_server_replica(shard, server);
}

void iproto_cluster_bulk(iproto_cluster_t *cluster, iproto_message_t **messages, int nmessages, struct timeval *timeout) {
    for (int i = 0; i < nmessages; i++)
        iproto_message_set_cluster(messages[i], cluster);
    iproto_bulk(messages, nmessages, timeout);
}

void iproto_cluster_do(iproto_cluster_t *cluster, iproto_message_t *message, struct timeval *timeout) {
    iproto_cluster_bulk(cluster, &message, 1, timeout);
}
