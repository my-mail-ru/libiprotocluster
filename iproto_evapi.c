#include "iproto_evapi.h"
#include <assert.h>
#include <stdlib.h>

static ev_io *xev_io_new(void (*cb)(struct ev_loop *, ev_io *, int)) {
    ev_io *io = malloc(sizeof(*io));
    ev_init(io, cb);
    return io;
}

static void xev_io_free(ev_io *io) {
    free(io);
}

static void xev_io_set(ev_io *io, int fd, int events) {
    ev_io_set(io, fd, events);
}

static void xev_io_get(ev_io *io, int *fd, int *events) {
    *fd = io->fd;
    *events = io->events;
}

static void xev_io_set_data(ev_io *io, void *data) {
    io->data = data;
}

static void *xev_io_data(ev_io *io) {
    return io->data;
}

static ev_timer *xev_timer_new(void (*cb)(struct ev_loop *, ev_timer *, int)) {
    ev_timer *timer = malloc(sizeof(*timer));
    ev_init(timer, cb);
    return timer;
}

static void xev_timer_free(ev_timer *timer) {
    free(timer);
}

static void xev_timer_set(ev_timer *timer, ev_tstamp after, ev_tstamp repeat) {
    ev_timer_set(timer, after, repeat);
}

static void xev_timer_set_data(ev_timer *timer, void *data) {
    timer->data = data;
}

static void *xev_timer_data(ev_timer *timer) {
    return timer->data;
}

iproto_evapi_t iproto_evapi = {
    .version = IPROTO_EVAPI_VERSION,
    .revision = IPROTO_EVAPI_REVISION,
    .loop = NULL,
    .loop_fork = ev_loop_fork,
    .now_update = ev_now_update,
    .run = ev_run,
    .break_ = ev_break,
    .suspend = ev_suspend,
    .resume = ev_resume,
    .io_new = xev_io_new,
    .io_free = xev_io_free,
    .io_set = xev_io_set,
    .io_get = xev_io_get,
    .io_set_data = xev_io_set_data,
    .io_data = xev_io_data,
    .io_start = ev_io_start,
    .io_stop = ev_io_stop,
    .timer_new = xev_timer_new,
    .timer_free = xev_timer_free,
    .timer_set = xev_timer_set,
    .timer_set_data = xev_timer_set_data,
    .timer_data = xev_timer_data,
    .timer_start = ev_timer_start,
    .timer_stop = ev_timer_stop,
    .timer_again = ev_timer_again
};

iproto_evapi_t iproto_evapi;

void iproto_evapi_initialize(void) {
    iproto_evapi.loop = EV_DEFAULT;
}

void iproto_set_evapi(iproto_evapi_t *evapi) {
    assert(evapi->version == IPROTO_EVAPI_VERSION && evapi->revision >= IPROTO_EVAPI_REVISION);
    iproto_evapi = *evapi;
}
