#ifndef IPROTOCLUSTER_H_INCLUDED
#define IPROTOCLUSTER_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#include <libiproto.h>

#define IPROTO_ERR_CODE_FLAG ((0x80 << 16) | LIBIPROTO_ERR_CODE_FLAG)
#define IPROTO_ERROR_CODES_OK(_) \
    _(ERR_CODE_OK,                (0x00), "ok")
#define IPROTO_ERROR_CODES(_) \
    _(ERR_CODE_TIMEOUT,             (0x01 << 16) | (IPROTO_ERR_CODE_FLAG | TEMPORARY_ERR_CODE_FLAG), "timeout") \
    _(ERR_CODE_CLUSTER_NOT_SET,     (0x02 << 16) | (IPROTO_ERR_CODE_FLAG | FATAL_ERR_CODE_FLAG), "cluster not set") \
    _(ERR_CODE_INVALID_SHARD_NUM,   (0x03 << 16) | (IPROTO_ERR_CODE_FLAG | FATAL_ERR_CODE_FLAG), "invalid shard_num") \
    _(ERR_CODE_LOSE_EARLY_RETRY,    (0x04 << 16) | (IPROTO_ERR_CODE_FLAG), "lose early retry") \
    _(ERR_CODE_NO_SERVER_AVAILABLE, (0x05 << 16) | (IPROTO_ERR_CODE_FLAG | TEMPORARY_ERR_CODE_FLAG), "no server available")
#define IPROTO_ALL_ERROR_CODES(x) IPROTO_ERROR_CODES_OK(x) IPROTO_ERROR_CODES(x) LIBIPROTO_ERROR_CODES(x)
#ifndef ERR_CODES_ENUM
typedef enum iproto_error ENUM_INITIALIZER(IPROTO_ALL_ERROR_CODES) iproto_error_t;
#else
typedef enum ERR_CODES_ENUM iproto_error_t;
#endif
#define iproto_error_string(e) errcode_desc(e)

#define ENUM_NOVAL_DEF(s) s,
#define ENUM_NOVAL_INITIALIZER(define) { define(ENUM_NOVAL_DEF) }

#define IPROTO_FROM(_) \
    _(FROM_MASTER) \
    _(FROM_REPLICA) \
    _(FROM_MASTER_REPLICA) \
    _(FROM_REPLICA_MASTER)
typedef enum iproto_from ENUM_NOVAL_INITIALIZER(IPROTO_FROM) iproto_from_t;

#define IPROTO_RETRY(_) \
    _(RETRY_EARLY,   0x01) \
    _(RETRY_SAFE,    0x02) \
    _(RETRY_SAME,    0x04)
typedef enum iproto_retry ENUM_INITIALIZER(IPROTO_RETRY) iproto_retry_t;

#define IPROTO_LOGLEVEL(_) \
    _(LOG_NOTHING,  0x00) \
    _(LOG_ERROR,    0x01) \
    _(LOG_WARNING,  0x02) \
    _(LOG_INFO,     0x03) \
    _(LOG_DEBUG,    0x04) \
    _(LOG_LEVEL,    0xff)
#define IPROTO_LOGTYPE(_) \
    _(LOG_DATA,     (0x000001 << 8)) \
    _(LOG_CONNECT,  (0x000002 << 8)) \
    _(LOG_IO,       (0x000004 << 8)) \
    _(LOG_EV,       (0x000008 << 8)) \
    _(LOG_TIME,     (0x000010 << 8)) \
    _(LOG_RETRY,    (0x000020 << 8)) \
    _(LOG_FORK,     (0x000040 << 8)) \
    _(LOG_STAT,     (0x000080 << 8)) \
    _(LOG_GRAPHITE, (0x000100 << 8)) \
    _(LOG_TYPE,     (0xffffff << 8))
#define IPROTO_LOGMASK(_) IPROTO_LOGLEVEL(_) IPROTO_LOGTYPE(_)
enum iproto_logmask ENUM_INITIALIZER(IPROTO_LOGMASK);
typedef enum iproto_logmask iproto_logmask_t;

typedef struct iproto_cluster iproto_cluster_t;
typedef struct iproto_shard iproto_shard_t;
typedef struct iproto_server iproto_server_t;
typedef struct iproto_message iproto_message_t;

typedef struct {
    struct timeval connect_timeout;
    struct timeval server_freeze;
} iproto_cluster_opts_t;

typedef void iproto_message_callback_t(iproto_message_t *message);
typedef bool iproto_message_soft_retry_callback_t(iproto_message_t *message);

typedef struct {
    int max_tries;
    unsigned shard_num;
    iproto_from_t from;
    iproto_retry_t retry;
    struct timeval timeout;
    struct timeval early_timeout;
    iproto_message_callback_t *callback;
    struct timeval soft_retry_delay_min;
    struct timeval soft_retry_delay_max;
    iproto_message_soft_retry_callback_t *soft_retry_callback;
} iproto_message_opts_t;

typedef struct {
    time_t registered;
    struct timeval wallclock;
    unsigned int count;
} iproto_stat_data_t;

typedef void iproto_stat_callback_t(const char *type, const char *server, iproto_error_t error, const iproto_stat_data_t *data);

void iproto_initialize(void);
void iproto_set_logmask(iproto_logmask_t mask);

void iproto_bulk(iproto_message_t **messages, int nmessages, struct timeval *timeout);
void iproto_do(iproto_message_t *message, struct timeval *timeout);

iproto_cluster_t *iproto_cluster_init(void);
void iproto_cluster_free(iproto_cluster_t *cluster);
iproto_cluster_opts_t *iproto_cluster_options(iproto_cluster_t *cluster);
void iproto_cluster_add_shard(iproto_cluster_t *cluster, iproto_shard_t *shard);
int iproto_cluster_get_shard_count(iproto_cluster_t *cluster);
void iproto_cluster_bulk(iproto_cluster_t *cluster, iproto_message_t **messages, int nmessages, struct timeval *timeout);
void iproto_cluster_do(iproto_cluster_t *cluster, iproto_message_t *message, struct timeval *timeout);

iproto_shard_t *iproto_shard_init(void);
void iproto_shard_free(iproto_shard_t *shard);
void iproto_shard_add_servers(iproto_shard_t *shard, bool replica, iproto_server_t **servers, int nservers);

iproto_server_t *iproto_server_init(char *host, int port);
void iproto_server_free(iproto_server_t *server);

iproto_message_t *iproto_message_init(int code, void *data, size_t size);
void iproto_message_free(iproto_message_t *message);
iproto_message_opts_t *iproto_message_options(iproto_message_t *message);
iproto_error_t iproto_message_error(iproto_message_t *message);
void *iproto_message_response(iproto_message_t *message, size_t *size, bool *replica);
iproto_cluster_t *iproto_message_get_cluster(iproto_message_t *message);
void iproto_message_set_cluster(iproto_message_t *message, iproto_cluster_t *cluster);

void iproto_stat_set_callback(iproto_stat_callback_t *callback);
void iproto_stat_set_flush_interval(time_t interval);
void iproto_stat_flush(void);

iproto_error_t iproto_stat_graphite_set(const char *host, short port, const char *prefix);

#endif
