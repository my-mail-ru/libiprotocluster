#include "iproto_private.h"

#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>
#include "khash.h"

KHASH_MAP_INIT_STR(pinger_servers, bool);
static khash_t(pinger_servers) *pinger_servers = NULL;
static time_t pinger_read_time = 0;

static void iproto_pinger_update(void) {
    if (pinger_read_time == time(NULL)) return;
    if (!pinger_servers)
        pinger_servers = kh_init(pinger_servers, NULL, realloc);
    khiter_t k;
    foreach (pinger_servers, k) {
        const char *key = kh_key(pinger_servers, k);
        free((char *)key);
    }
    kh_clear(pinger_servers, pinger_servers);
    int shmid = shmget(0x2afedead, 65536, 0);
    if (shmid != -1) {
        void *data = shmat(shmid, NULL, SHM_RDONLY);
        char *str = (char *)data;
        char *next;
        while (str && (next = strstr(str, "iproto:"))) {
            next += 7;
            char *hostport;
            char *end = index(next, ',');
            if (end) {
                size_t len = end - next;
                hostport = malloc(len + 1);
                memcpy(hostport, next, len);
                hostport[len] = '\0';
            } else {
                hostport = strdup(next);
            }
            int ret;
            khiter_t k = kh_put(pinger_servers, pinger_servers, hostport, &ret);
            kh_value(pinger_servers, k) = false;
            str = end;
        }
        shmdt(data);
    } else {
        iproto_log(LOG_WARNING, "failed to shmget() pinger shared memory: %m");
    }
    time(&pinger_read_time);
}

bool iproto_server_is_pingable(iproto_server_t *server) {
    iproto_pinger_update();
    const char *hostport = iproto_server_hostport(server);
    khiter_t k = kh_get(pinger_servers, pinger_servers, hostport);
    bool pingable = k == kh_end(pinger_servers);
    if (!pingable && !kh_value(pinger_servers, k)) {
        iproto_log(LOG_WARNING, "server %s: not pingable", hostport);
        kh_value(pinger_servers, k) = true;
    }
    return pingable;
}
