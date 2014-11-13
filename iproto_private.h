#ifndef IPROTO_PRIVATE_H_INCLUDED
#define IPROTO_PRIVATE_H_INCLUDED

#include "iprotocluster.h"
#include "iproto_util.h"
#include "iproto_config.h"

#if (__WORDSIZE == 64)
#define kh_req_hash_func(key) kh_int64_hash_func((int64_t)key)
#define kh_req_hash_equal(a, b) kh_int64_hash_equal(a, b)
#else
#define kh_req_hash_func(key) kh_int_hash_func(key)
#define kh_req_hash_equal(a, b) kh_int_hash_equal(a, b)
#endif

typedef struct iproto_stat iproto_stat_t;

void iproto_init_globals(void);
void iproto_free_globals(void);

iproto_server_t *iproto_cluster_get_server(iproto_cluster_t *cluster, iproto_message_t *message, iproto_server_t **not_servers, int n_not_servers);
bool iproto_cluster_is_server_replica(iproto_cluster_t *cluster, iproto_message_t *message, iproto_server_t *server);

iproto_server_t *iproto_shard_get_server(iproto_shard_t *shard, iproto_message_t *message, iproto_server_t **not_servers, int n_not_servers, const struct timeval *server_freeze);
bool iproto_shard_is_server_replica(iproto_shard_t *shard, iproto_server_t *server);
void iproto_shard_move_server_to_tail(iproto_shard_t *shard, iproto_server_t *server);

const char *iproto_server_hostport(iproto_server_t *server);
void iproto_server_add_to_shard(iproto_server_t *server, iproto_shard_t *shard);
void iproto_server_remove_from_shard(iproto_server_t *server, iproto_shard_t *shard);
bool iproto_server_is_active(iproto_server_t *server, const struct timeval *server_freeze);
int iproto_server_get_fd(iproto_server_t *server);
void iproto_server_send(iproto_server_t *server, iproto_message_t *message);
iproto_message_t *iproto_server_recv(iproto_server_t *server);
void iproto_server_remove_message(iproto_server_t *server, iproto_message_t *message, struct iproto_request_t *request, iproto_error_t error);
void iproto_server_handle_io(iproto_server_t *server, short revents);
void iproto_server_handle_error(iproto_server_t *server, iproto_error_t error);
void iproto_server_insert_request_stat(iproto_server_t *server, iproto_error_t error, struct timeval *start_time);
void iproto_server_close_all(void);

bool iproto_message_in_progress(iproto_message_t *message);
bool iproto_message_soft_retry(iproto_message_t *message, struct timeval *delay);
bool iproto_message_can_try(iproto_message_t *message);
bool iproto_message_retry_same(iproto_message_t *message);
uint32_t iproto_message_get_request(iproto_message_t *message, void **data, size_t *size);
void iproto_message_set_response(iproto_message_t *message, iproto_server_t *server, iproto_error_t error, void *data, size_t size);
void iproto_message_insert_request(iproto_message_t *message, iproto_server_t *server, struct iproto_request_t *request);
void iproto_message_remove_request(iproto_message_t *message, iproto_server_t *server, struct iproto_request_t *request);
int iproto_message_clear_requests(iproto_message_t *message, iproto_error_t error);
void iproto_message_while_request_server(iproto_message_t *message, void (*callback)(iproto_server_t *server));
struct timeval *iproto_message_request_start_time(iproto_message_t *message, iproto_server_t *server);

iproto_stat_t *iproto_stat_init(const char *type, const char *server);
void iproto_stat_free(iproto_stat_t *stat);
void iproto_stat_insert(iproto_stat_t *stat, iproto_error_t error, struct timeval *start_time);
void iproto_stat_insert_duration(iproto_stat_t *stat, iproto_error_t error, struct timeval *duration);
void iproto_stat_maybe_flush(void);

extern iproto_logmask_t iproto_logmask;

#define iproto_is_loggable(mask) \
    (((mask) & LOG_LEVEL) <= (iproto_logmask & LOG_LEVEL) || ((mask) & iproto_logmask & LOG_TYPE) != 0)

#define iproto_log(mask, format, ...) \
    if (iproto_is_loggable(mask)) \
        iproto_util_log(mask, "iproto: " format, ##__VA_ARGS__)

#define iproto_log_data(mask, data, length, format, ...) \
    if (iproto_is_loggable(mask)) \
        iproto_util_log_data(mask, data, length, "iproto: " format, ##__VA_ARGS__)

#ifdef WITH_GRAPHITE
void iproto_stat_graphite_send(const char *type, const char *server, iproto_error_t error, iproto_stat_data_t *data);
void iproto_stat_graphite_flush(void);
#else
#define iproto_stat_graphite_send(type, server, error, data)
#define iproto_stat_graphite_flush()
#endif

#ifdef MY_MAIL_RU
bool iproto_server_is_pingable(iproto_server_t *server);
#else
#define iproto_server_is_pingable(server) true
#endif

#endif
