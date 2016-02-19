#include <stdlib.h>
#include "dslink/mem/mem.h"
#include "dslink/col/listener.h"


Listener *listener_add(Dispatcher *dispatcher, int (*callback)(Listener *, void *), void *data) {
    Listener *listener = dslink_malloc(sizeof(Listener));
    listener->callback = callback;
    listener->data = data;
    list_insert_node(&dispatcher->list, listener);
    return listener;
}

void listener_dispatch_message(Dispatcher *dispatcher, void *message) {
    ListNodeBase *next;
    for (ListNodeBase *node = dispatcher->list.head.next;
         node != &dispatcher->list.head;
         node = next) {
        Listener *listener = (Listener *)node;

        // fetch the next node first
        next = node->next;

        // callback can safely remove and free the listener
        listener->callback(listener, message);
    }
}

void listener_dispatch_remove_all(Dispatcher *dispatcher, void *message) {
    ListNodeBase *next;
    for (ListNodeBase *node = dispatcher->list.head.next;
         node != &dispatcher->list.head;
         node = next) {
        Listener *listener = (Listener *)node;

        // fetch the next node first
        next = node->next;

        // clear it from the list
        listener->list = NULL;

        // callback can safely free the listener
        listener->callback(listener, message);
    }
    dispatcher->list.head.next = &dispatcher->list.head;
    dispatcher->list.head.prev = &dispatcher->list.head;
}
