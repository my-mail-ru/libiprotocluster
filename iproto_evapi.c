#include "iproto_evapi.h"
#include "iproto_private.h"
#include <assert.h>
#include <stdlib.h>
#include <dlfcn.h>

iproto_evapi_t iproto_evapi;

static bool evapi_set = false;
static void *handle = NULL;

static void set_evapi(iproto_evapi_t *evapi) {
    assert(evapi->version == IPROTO_EVAPI_VERSION && evapi->revision >= IPROTO_EVAPI_REVISION);
    iproto_evapi = *evapi;
    evapi_set = true;
}

void iproto_set_evapi(iproto_evapi_t *evapi) {
    if (handle) {
        dlclose(handle);
        handle = NULL;
    }
    set_evapi(evapi);
}

void iproto_evapi_initialize(void) {
    if (evapi_set)
        return;
    handle = dlopen("libiprotocluster_ev.so", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        iproto_log(LOG_ERROR | LOG_EV, "Failed to dlopen(): %s", dlerror());
        abort();
    }
    iproto_evapi_t *(*evapi_ev)(void);
    evapi_ev = (iproto_evapi_t *(*)(void))dlsym(handle, "iproto_evapi_ev");
    set_evapi((*evapi_ev)());
}
