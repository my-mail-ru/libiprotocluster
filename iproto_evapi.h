#ifndef IPROTO_EVAPI_H_INCLUDED
#define IPROTO_EVAPI_H_INCLUDED

#ifdef FAKE_EV
struct ev_loop;
typedef struct ev_io ev_io;
typedef struct ev_timer ev_timer;
typedef double ev_tstamp;
#else
#include <ev.h>
#endif

#define IPROTO_EVAPI_VERSION 2
#define IPROTO_EVAPI_REVISION 0
typedef struct {
    int version;
    int revision;
    struct ev_loop *loop;
    void (*loop_fork)(struct ev_loop *);
    void (*now_update)(struct ev_loop *);
    void (*iproto_run)(struct ev_loop *, void **data);
    void (*iproto_ready)(struct ev_loop *, void *data);
    void (*suspend)(struct ev_loop *); 
    void (*resume) (struct ev_loop *); 
    ev_io *(*io_new)(void (*)(struct ev_loop *, ev_io *, int));
    void (*io_free)(ev_io *);
    void (*io_set)(ev_io *, int, int);
    void (*io_get)(ev_io *, int *, int *);
    void (*io_set_data)(ev_io *, void *);
    void *(*io_data)(ev_io *);
    void (*io_start)(struct ev_loop *, ev_io *);
    void (*io_stop) (struct ev_loop *, ev_io *);
    ev_timer *(*timer_new)(void (*)(struct ev_loop *, ev_timer *, int));
    void (*timer_free)(ev_timer *);
    void (*timer_set)(ev_timer *, ev_tstamp, ev_tstamp);
    void (*timer_set_data)(ev_timer *, void *);
    void *(*timer_data)(ev_timer *);
    void (*timer_start)(struct ev_loop *, ev_timer *);
    void (*timer_stop) (struct ev_loop *, ev_timer *);
    void (*timer_again)(struct ev_loop *, ev_timer *);
} iproto_evapi_t;

void iproto_set_evapi(iproto_evapi_t *evapi);

#endif
