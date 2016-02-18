#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct iproto_message_ev {
    iproto_message_t *message;
    struct ev_loop *loop;
    ev_timer *early_timeout;
    ev_timer *timeout;
    ev_timer *soft_retry_timer;
    iproto_server_t *last_server;
    void *data;
    bool started;
};

static void iproto_message_ev_early_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void iproto_message_ev_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void iproto_message_ev_soft_retry_cb(struct ev_loop *loop, ev_timer *w, int revents);

iproto_message_ev_t *iproto_message_ev_init(iproto_message_t *message) {
    iproto_message_ev_t *ev = malloc(sizeof(*ev));
    memset(ev, 0, sizeof(*ev));
    ev->loop = EV_DEFAULT;
    ev->message = message;
    ev->timeout = ev_timer_new(iproto_message_ev_timeout_cb);
    ev_timer_set_priority(ev->timeout, IPROTO_TIMEOUTPRI);
    ev_timer_set_data(ev->timeout, ev);
    return ev;
}

void iproto_message_ev_free(iproto_message_ev_t *ev) {
    ev_timer_free(ev->timeout);
    if (ev->early_timeout)
        ev_timer_free(ev->early_timeout);
    if (ev->soft_retry_timer)
        ev_timer_free(ev->soft_retry_timer);
    free(ev);
}

void iproto_message_ev_start(iproto_message_ev_t *ev) {
    if (ev->started)
        return;
    ev->started = true;
    iproto_message_opts_t *opts = iproto_message_options(ev->message);
    if (opts->retry & RETRY_EARLY) {
        if (!ev->early_timeout) {
            ev->early_timeout = ev_timer_new(iproto_message_ev_early_timeout_cb);
            ev_timer_set_priority(ev->early_timeout, IPROTO_TIMEOUTPRI);
            ev_timer_set_data(ev->early_timeout, ev);
        }
        ev_timer_set(ev->early_timeout, timeval2ev(opts->early_timeout), 0);
        ev_timer_start(ev->loop, ev->early_timeout);
    }
    ev_timer_set(ev->timeout, timeval2ev(opts->timeout), 0);
    ev_timer_start(ev->loop, ev->timeout);
}

void iproto_message_ev_stop(iproto_message_ev_t *ev) {
    ev->started = false;
    ev_timer_stop(ev->loop, ev->timeout);
    if (ev->early_timeout)
        ev_timer_stop(ev->loop, ev->early_timeout);
    if (ev->soft_retry_timer)
        ev_timer_stop(ev->loop, ev->soft_retry_timer);
}

static void iproto_message_ev_done(iproto_message_ev_t *ev) {
    assert(iproto_message_error(ev->message) != ERR_CODE_REQUEST_IN_PROGRESS);
    iproto_message_opts_t *opts = iproto_message_options(ev->message);
    iproto_message_ev_stop(ev);
    if (opts->callback)
        opts->callback(ev->message);
}

static void iproto_message_ev_soft_retry(iproto_message_ev_t *ev, struct timeval *delay) {
    iproto_log(LOG_DEBUG | LOG_EV, "message %p: soft retry after %d.%06d sec.", ev->message, delay->tv_sec, delay->tv_usec);
    if (!ev->soft_retry_timer) {
        ev->soft_retry_timer = ev_timer_new(iproto_message_ev_soft_retry_cb);
        ev_timer_set_priority(ev->soft_retry_timer, IPROTO_TIMEOUTPRI);
        ev_timer_set_data(ev->soft_retry_timer, ev);
    } else {
        ev_timer_stop(ev->loop, ev->soft_retry_timer);
    }
    ev_timer_set(ev->soft_retry_timer, timeval2ev(*delay), 0);
    ev_timer_start(ev->loop, ev->soft_retry_timer);
}

static void iproto_message_ev_send(iproto_message_ev_t *ev) {
    iproto_cluster_t *cluster = iproto_message_get_cluster(ev->message);
    iproto_server_t *server = ev->last_server && iproto_message_retry_same(ev->message) ? ev->last_server
        : iproto_cluster_get_server(cluster, ev->message, NULL, 0);
    if (server == NULL) {
        iproto_message_ev_done(ev);
    } else {
        iproto_server_send(server, ev->message);
        ev->last_server = server;
    }
}

static void iproto_message_ev_early_retry(iproto_message_ev_t *ev) {
    iproto_cluster_t *cluster = iproto_message_get_cluster(ev->message);
    iproto_server_t *srvs[3];
    srvs[0] = ev->last_server;
    for (int t = 1; t < 3; t++) {
        srvs[t] = iproto_cluster_get_server(cluster, ev->message, srvs, t);
        if (srvs[t])
            iproto_server_send(srvs[t], ev->message);
    }
    iproto_log(LOG_WARNING | LOG_RETRY, "early retry for %s - %s and %s", iproto_server_hostport(srvs[0]),
        srvs[1] ? iproto_server_hostport(srvs[1]) : "nothing",
        srvs[2] ? iproto_server_hostport(srvs[2]) : "nothing");
}

void iproto_message_ev_dispatch(iproto_message_ev_t *ev, bool finish) {
    if (iproto_message_error(ev->message) == ERR_CODE_OK) {
        struct timeval soft_retry_delay;
        if (iproto_message_soft_retry(ev->message, &soft_retry_delay)) {
            iproto_message_ev_soft_retry(ev, &soft_retry_delay);
        } else {
            iproto_message_clear_requests(ev->message, ERR_CODE_LOSE_EARLY_RETRY);
            iproto_message_ev_done(ev);
        }
    } else if (finish || !iproto_message_can_try(ev->message)) {
        if (!iproto_message_in_progress(ev->message))
            iproto_message_ev_done(ev);
    } else {
        iproto_message_ev_send(ev);
    }
}

void iproto_message_ev_set_data(iproto_message_ev_t *ev, void *data) {
    ev->data = data;
}

void *iproto_message_ev_data(iproto_message_ev_t *ev) {
    return ev->data;
}

static void iproto_message_ev_early_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)ev_timer_data(w);
    iproto_message_opts_t *opts = iproto_message_options(ev->message);
    iproto_log(LOG_WARNING | LOG_EV, "message %p: early timeout (%d.%06d), server %s",
        ev->message, opts->early_timeout.tv_sec, opts->early_timeout.tv_usec, iproto_server_hostport(ev->last_server));
    ev_timer_stop(loop, w);
    iproto_message_ev_early_retry(ev);
}

static void iproto_message_ev_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)ev_timer_data(w);
    iproto_message_opts_t *opts = iproto_message_options(ev->message);
    iproto_log(LOG_WARNING | LOG_EV, "message %p: timeout (%d.%06d), server %s",
        ev->message, opts->timeout.tv_sec, opts->timeout.tv_usec, iproto_server_hostport(ev->last_server));
    ev_timer_stop(loop, w);
    assert(iproto_message_in_progress(ev->message));
    iproto_message_set_response(ev->message, ev->last_server, ERR_CODE_TIMEOUT, NULL, 0);
    iproto_message_clear_requests(ev->message, ERR_CODE_TIMEOUT);
    iproto_message_ev_dispatch(ev, false);
}

static void iproto_message_ev_soft_retry_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)ev_timer_data(w);
    iproto_log(LOG_DEBUG | LOG_EV, "message %p: soft retry timer", ev->message);
    ev_timer_stop(loop, w);
    iproto_message_ev_dispatch(ev, false);
}
