#include "iproto_private.h"

#include <sys/queue.h>
#include <time.h>
#include <unistd.h>
#include "khash.h"

struct server_entry {
    iproto_server_t *server;
    TAILQ_ENTRY(server_entry) link;
};

struct priority_entry {
    TAILQ_HEAD(priority_servers, server_entry) servers;
    TAILQ_ENTRY(priority_entry) link;
};

KHASH_INIT(shard_server_types, iproto_server_t *, bool, 1, kh_req_hash_func, kh_req_hash_equal);

struct iproto_shard {
    TAILQ_HEAD(priorities, priority_entry) masters, replicas;
    khash_t(shard_server_types) *server_types;
    struct {
        iproto_server_t *masters[3];
        iproto_server_t *replicas[3];
    } current;
};

iproto_shard_t *iproto_shard_init(void) {
    iproto_shard_t *shard = malloc(sizeof(iproto_shard_t));
    memset(shard, 0, sizeof(iproto_shard_t));
    TAILQ_INIT(&shard->masters);
    TAILQ_INIT(&shard->replicas);
    shard->server_types = kh_init(shard_server_types, NULL, kh_realloc);
    return shard;
}

void iproto_shard_free(iproto_shard_t *shard) {
    kh_destroy(shard_server_types, shard->server_types);
    for (int r = 0; r < 2; r++) {
        struct priorities *priorities = r ? &shard->replicas : &shard->masters;
        struct priority_entry *priority;
        while ((priority = TAILQ_FIRST(priorities))) {
            struct priority_servers *head = &priority->servers;
            struct server_entry *entry;
            while ((entry = TAILQ_FIRST(head))) {
                iproto_server_remove_from_shard(entry->server, shard);
                TAILQ_REMOVE(head, entry, link);
                free(entry);
            }
            TAILQ_REMOVE(priorities, priority, link);
            free(priority);
        }
    }
    free(shard);
}

void iproto_shard_add_servers(iproto_shard_t *shard, bool replica, iproto_server_t **servers, int nservers) {
    struct priorities *priorities = replica ? &shard->replicas : &shard->masters;
    struct priority_entry *priority = malloc(sizeof(*priority));
    struct priority_servers *head = &priority->servers;
    TAILQ_INIT(head);
    iproto_server_t **shuffled = malloc(nservers * sizeof(*shuffled));
    if (nservers > 0) {
        static unsigned int seed;
        static bool seed_ready = false;
        if (!seed_ready) {
            seed = time(NULL) * getpid();
            seed_ready = true;
        }
        shuffled[0] = servers[0];
        for (int i = 1; i < nservers; i++) {
            int j = rand_r(&seed) % (i + 1);
            shuffled[i] = shuffled[j];
            shuffled[j] = servers[i];
        }
    }
    for (int i = 0; i < nservers; i++) {
        struct server_entry *entry = malloc(sizeof(*entry));
        entry->server = shuffled[i];
        iproto_server_add_to_shard(entry->server, shard);
        TAILQ_INSERT_TAIL(head, entry, link);
        int ret;
        khiter_t k = kh_put(shard_server_types, shard->server_types, entry->server, &ret);
        if (ret || !replica) kh_value(shard->server_types, k) = replica;
    }
    free(shuffled);
    TAILQ_INSERT_TAIL(priorities, priority, link);
}

iproto_server_t *iproto_shard_get_server(iproto_shard_t *shard, iproto_message_t *message, iproto_server_t **not_servers, int n_not_servers, const struct timeval *server_freeze) {
    iproto_message_opts_t *opts = iproto_message_options(message);
    bool replica = opts->from == FROM_REPLICA || opts->from == FROM_REPLICA_MASTER;
    bool both = opts->from == FROM_MASTER_REPLICA || opts->from == FROM_REPLICA_MASTER;
    for (int skip_active_check = 0; skip_active_check < 2; skip_active_check++) {
        for (int r = 0; r < (both ? 2 : 1); r++) {
            struct priorities *priorities = replica != r ? &shard->replicas : &shard->masters;
            struct priority_entry *priority;
            TAILQ_FOREACH (priority, priorities, link) {
                struct server_entry *entry;
                TAILQ_FOREACH (entry, &priority->servers, link) {
                    iproto_server_t *server = entry->server;
                    bool ok = true;
                    if (not_servers != NULL) {
                        for (int i = 0; i < n_not_servers; i++) {
                            if (not_servers[i] == server) {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if (ok && iproto_server_is_pingable(server) && (skip_active_check || iproto_server_is_active(server, server_freeze))) return server;
                }
            }
        }
    }
    iproto_log(LOG_WARNING, "no active servers found for message %p", message);
    if (not_servers == NULL)
        iproto_message_set_response(message, NULL, ERR_CODE_NO_SERVER_AVAILABLE, NULL, 0);
    return NULL;
}

void iproto_shard_move_server_to_tail(iproto_shard_t *shard, iproto_server_t *server) {
    for (int r = 0; r < 2; r++) {
        struct priorities *priorities = r ? &shard->replicas : &shard->masters;
        struct priority_entry *priority;
        TAILQ_FOREACH (priority, priorities, link) {
            struct server_entry *entry;
            TAILQ_FOREACH_REVERSE (entry, &priority->servers, priority_servers, link) {
                if (entry->server == server) {
                    struct server_entry *next = TAILQ_NEXT(entry, link);
                    if (next) {
                        TAILQ_REMOVE(&priority->servers, entry, link);
                        TAILQ_INSERT_TAIL(&priority->servers, entry, link);
                        entry = next;
                    }
                }
            }
        }
    }
}

bool iproto_shard_is_server_replica(iproto_shard_t *shard, iproto_server_t *server) {
    khiter_t k = kh_get(shard_server_types, shard->server_types, server);
    if (k == kh_end(shard->server_types)) return -1;
    return kh_value(shard->server_types, k);
}
