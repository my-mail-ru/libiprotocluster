#include "iproto_private.h"
#include "iproto_private_ev.h"

#include <stdlib.h>
#include <string.h>

struct iproto_message_ev {
    iproto_message_t *message;
    struct ev_loop *loop;
    ev_timer *early_timeout;
    ev_timer *timeout;
    ev_timer *soft_retry_timer;
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

void iproto_message_ev_soft_retry(iproto_message_ev_t *ev, struct timeval *delay) {
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

void iproto_message_ev_set_data(iproto_message_ev_t *ev, void *data) {
    ev->data = data;
}

void *iproto_message_ev_data(iproto_message_ev_t *ev) {
    return ev->data;
}

static void iproto_message_ev_early_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)ev_timer_data(w);
    ev_timer_stop(loop, w);
    iproto_message_early_retry(ev->message);
}

static void iproto_message_ev_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)ev_timer_data(w);
    ev_timer_stop(loop, w);
    iproto_message_handle_timeout(ev->message);
}

static void iproto_message_ev_soft_retry_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    iproto_message_ev_t *ev = (iproto_message_ev_t *)ev_timer_data(w);
    iproto_log(LOG_DEBUG | LOG_EV, "message %p: soft retry timer", ev->message);
    ev_timer_stop(loop, w);
    iproto_message_dispatch(ev->message, false);
}
