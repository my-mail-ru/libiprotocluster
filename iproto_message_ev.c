#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <libev/ev.h>

struct iproto_message_ev {
    iproto_message_t *message;
    struct ev_loop *loop;
    ev_timer *early_timeout;
    ev_timer *timeout;
    ev_timer *soft_retry_timer;
    iproto_server_t *last_server;
};

static void iproto_message_ev_early_timeout_cb(EV_P_ ev_timer *w, int revents);
static void iproto_message_ev_timeout_cb(EV_P_ ev_timer *w, int revents);
static void iproto_message_ev_soft_retry_cb(EV_P_ ev_timer *w, int revents);

iproto_message_ev_t *iproto_message_ev_init(iproto_message_t *message) {
    iproto_message_ev_t *ev = malloc(sizeof(*ev));
    memset(ev, 0, sizeof(*ev));
    ev->message = message;
    ev->timeout = malloc(sizeof(*ev->timeout));
    ev->timeout->data = ev;
    ev_init(ev->timeout, iproto_message_ev_timeout_cb);
    return ev;
}

void iproto_message_ev_free(iproto_message_ev_t *ev) {
    free(ev->timeout);
    free(ev);
}

void iproto_message_ev_start(iproto_message_ev_t *ev, struct ev_loop *loop) {
    ev->loop = loop;
    iproto_message_opts_t *opts = iproto_message_options(ev->message);
    if (opts->retry & RETRY_EARLY) {
        ev->early_timeout = malloc(sizeof(*ev->early_timeout));
        ev->early_timeout->data = ev;
        ev_timer_init(ev->early_timeout, iproto_message_ev_early_timeout_cb, timeval2ev(opts->early_timeout), 0);
        ev_timer_start(loop, ev->early_timeout);
    }
    ev_timer_set(ev->timeout, 0, timeval2ev(opts->timeout));
}

static void iproto_message_ev_stop(iproto_message_ev_t *ev) {
    if (ev->early_timeout) {
        ev_timer_stop(ev->loop, ev->early_timeout);
        free(ev->early_timeout);
    }
    ev_timer_stop(ev->loop, ev->timeout);
    if (ev->soft_retry_timer) {
        ev_timer_stop(ev->loop, ev->soft_retry_timer);
        free(ev->soft_retry_timer);
    }
}

struct ev_loop *iproto_message_ev_loop(iproto_message_ev_t *ev) {
    return ev->loop;
}

void iproto_message_ev_start_timer(iproto_message_ev_t *ev) {
    ev_timer_again(ev->loop, ev->timeout);
}

void iproto_message_ev_stop_timer(iproto_message_ev_t *ev) {
    ev_timer_stop(ev->loop, ev->timeout);
}

static void iproto_message_ev_done(iproto_message_ev_t *ev) {
    iproto_message_opts_t *opts = iproto_message_options(ev->message);
    if (opts->callback)
        opts->callback(ev->message);
    iproto_message_ev_stop(ev);
}

static void iproto_message_ev_soft_retry(iproto_message_ev_t *ev, struct timeval *delay) {
    iproto_log(LOG_DEBUG | LOG_EV, "message %p: soft retry after %d.%06d sec.", ev->message, delay->tv_sec, delay->tv_usec);
    if (!ev->soft_retry_timer) {
        ev->soft_retry_timer = malloc(sizeof(*ev->soft_retry_timer));
        ev->soft_retry_timer->data = ev;
        ev_timer_init(ev->soft_retry_timer, iproto_message_ev_soft_retry_cb, timeval2ev(*delay), 0);
    } else {
        ev_timer_stop(ev->loop, ev->soft_retry_timer);
        ev_timer_set(ev->soft_retry_timer, timeval2ev(*delay), 0);
    }
    ev_timer_start(ev->loop, ev->soft_retry_timer);
}

static void iproto_message_ev_send(iproto_message_ev_t *ev) {
    iproto_message_opts_t *opts = iproto_message_options(ev->message);
    iproto_cluster_t *cluster = iproto_message_get_cluster(ev->message);
    iproto_server_t *server = ev->last_server && (opts->retry & RETRY_SAME) ? ev->last_server
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

static void iproto_message_ev_early_timeout_cb(EV_P_ ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)w->data;
    iproto_log(LOG_WARNING | LOG_EV, "message %p: early timeout", ev->message);
    ev_timer_stop(EV_A_ w);
    iproto_message_ev_early_retry(ev);
}

static void iproto_message_ev_timeout_cb(EV_P_ ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)w->data;
    iproto_log(LOG_WARNING | LOG_EV, "message %p: timeout", ev->message);
    ev_timer_stop(EV_A_ w);
    assert(iproto_message_in_progress(ev->message));
    iproto_message_set_response(ev->message, ev->last_server, ERR_CODE_TIMEOUT, NULL, 0);
    iproto_message_clear_requests(ev->message, ERR_CODE_TIMEOUT);
    iproto_server_handle_message_timeout(ev->last_server);
    iproto_message_ev_dispatch(ev, false);
}

static void iproto_message_ev_soft_retry_cb(EV_P_ ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)w->data;
    iproto_log(LOG_DEBUG | LOG_EV, "message %p: soft retry timer", ev->message);
    ev_timer_stop(EV_A_ w);
    iproto_message_ev_dispatch(ev, false);
}
