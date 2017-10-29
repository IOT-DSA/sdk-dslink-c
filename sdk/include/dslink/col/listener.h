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

static inline
void listener_free_all(Dispatcher *dispatcher) {
    dslink_list_foreach_nonext(&dispatcher->list) {
        ListNode *entry = (ListNode *) node;
        entry->list = NULL; //avoid list_remove_node
        void *val = entry->value;
        ListNodeBase *tmp = node->next;
        if ((intptr_t) node != (intptr_t) val) {
            dslink_free(node);
        }
        node = tmp;
    }
    dispatcher->list.head.next = &dispatcher->list.head;
    dispatcher->list.head.prev = &dispatcher->list.head;
    dispatcher->list.size = 0;
}

#ifdef __cplusplus
}
#endif


#endif //SDK_DSLINK_C_LISTENER_H
