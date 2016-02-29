#ifndef SDK_DSLINK_C_LISTENER_H
#define SDK_DSLINK_C_LISTENER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "list.h"

typedef struct Listener {
    struct Listener *prev;
    struct Listener *next;
    List *list;

    // callback(data, message)
    int (*callback)(struct Listener *, void *);
    void *data;
} Listener;

typedef struct Dispatcher {
    // list of Listener
    List list;
} Dispatcher;

// listener instance created by add_listener need to be freed in user code
Listener *listener_add(Dispatcher *dispatcher, int (*callback)(Listener *, void *), void *data);

void listener_dispatch_message(Dispatcher *dispatcher, void *message);

// dispatch message and remove all listeners
void listener_dispatch_remove_all(Dispatcher *dispatcher, void *message);

static inline
Listener *listener_remove(Listener *listener){
    return (Listener *)list_remove_node(listener);
}

static inline
void listener_init(Dispatcher *dispatcher) {
    list_init(&dispatcher->list);
}

static inline
void listener_remove_all(Dispatcher *dispatcher) {
    list_remove_all_nodes(&dispatcher->list);
}

#ifdef __cplusplus
}
#endif


#endif //SDK_DSLINK_C_LISTENER_H
