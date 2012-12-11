#ifndef IPROTOCLUSTER_H_INCLUDED
#define IPROTOCLUSTER_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

#include <iproto_def.h>
#include <libiproto.h>

#define IPROTO_ERR_CODE_FLAG ((0x80 << 16) | LIBIPROTO_ERR_CODE_FLAG)
#define IPROTO_ERROR_CODES(_) \
    _(ERR_CODE_TIMEOUT,           (0x01 << 16) | (IPROTO_ERR_CODE_FLAG | TEMPORARY_ERR_CODE_FLAG), "timeout") \
    _(ERR_CODE_POLL,              (0x02 << 16) | (IPROTO_ERR_CODE_FLAG | TEMPORARY_ERR_CODE_FLAG), "poll() failed") \
    _(ERR_CODE_INVALID_SHARD_NUM, (0x03 << 16) | (IPROTO_ERR_CODE_FLAG | FATAL_ERR_CODE_FLAG), "invalid shard_num") \
    _(ERR_CODE_LOSE_EARLY_RETRY,  (0x04 << 16) | (IPROTO_ERR_CODE_FLAG), "lose early retry")
#define IPROTO_ALL_ERROR_CODES(x) IPROTO_ERROR_CODES(x) LIBIPROTO_ERROR_CODES(x) ERROR_CODES(x)
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
    _(RETRY_ANOTHER) \
    _(RETRY_SAME)
typedef enum iproto_retry ENUM_NOVAL_INITIALIZER(IPROTO_RETRY) iproto_retry_t;

#define IPROTO_LOGMASK(_) \
    _(LOG_NOTHING,  0x00) \
    _(LOG_ERROR,    0x01) \
    _(LOG_WARNING,  0x02) \
    _(LOG_INFO,     0x03) \
    _(LOG_DEBUG,    0x04) \
    _(LOG_LEVEL,    0xff) \
    _(LOG_DATA,     (0x000001 << 8)) \
    _(LOG_CONNECT,  (0x000002 << 8)) \
    _(LOG_IO,       (0x000004 << 8)) \
    _(LOG_POLL,     (0x000008 << 8)) \
    _(LOG_TIME,     (0x000010 << 8)) \
    _(LOG_RETRY,    (0x000020 << 8)) \
    _(LOG_FORK,     (0x000040 << 8)) \
    _(LOG_STAT,     (0x000080 << 8)) \
    _(LOG_GRAPHITE, (0x000100 << 8)) \
    _(LOG_TYPE,     (0xffffff << 8))
enum iproto_logmask ENUM_INITIALIZER(IPROTO_LOGMASK);
typedef enum iproto_logmask iproto_logmask_t;

typedef struct iproto_cluster iproto_t;
typedef struct iproto_shard iproto_shard_t;
typedef struct iproto_server iproto_server_t;
typedef struct iproto_message iproto_message_t;

typedef struct {
    struct timeval request_timeout;
    struct timeval first_timeout;
    struct timeval server_freeze;
    int max_tries;
    iproto_retry_t retry;
} iproto_opts_t;

typedef struct {
    int max_tries;
    unsigned shard_num;
    iproto_from_t from;
    bool early_retry;
} iproto_message_opts_t;

typedef struct {
    time_t registered;
    struct timeval wallclock;
    unsigned int count;
} iproto_stat_data_t;

typedef void iproto_stat_callback_t(const char *type, const char *server, iproto_error_t error, const iproto_stat_data_t *data);

void iproto_initialize(void);
void iproto_set_logmask(iproto_logmask_t mask);

iproto_t *iproto_init(void);
void iproto_free(iproto_t *iproto);
void iproto_add_shard(iproto_t *iproto, iproto_shard_t *shard);
void iproto_bulk(iproto_t *iproto, iproto_message_t **messages, int nmessages, iproto_opts_t *opts);
void iproto_do(iproto_t *iproto, iproto_message_t *message, iproto_opts_t *opts);

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

void iproto_stat_set_callback(iproto_stat_callback_t *callback);
void iproto_stat_set_flush_interval(time_t interval);

iproto_error_t iproto_stat_graphite_set(const char *host, short port, const char *prefix);

#endif
