#include <stdlib.h>
#include <string.h>
#include "dslink/col/listener.h"


Listener *listener_add(Dispatcher *dispatcher, int (*callback)(void *, void *), void *data) {
    Listener *listener = malloc(sizeof(Listener));
    listener->callback = callback;
    listener->data = data;
    list_insert_node(&dispatcher->list, listener);
    return listener;
}

void listener_dispatch_message(Dispatcher *dispatcher, void *message) {
    dslink_list_foreach(&dispatcher->list) {
        Listener *listener = (Listener *)node;
        listener->callback(listener->data, message);
    }
}

void listener_dispatch_remove_all(Dispatcher *dispatcher, void *message) {
    dslink_list_foreach(&dispatcher->list) {
        Listener *listener = (Listener *)node;
        listener->callback(listener->data, message);
        // clear it from the list
        listener->list = NULL;
    }
    dispatcher->list.head.next = &dispatcher->list.head;
    dispatcher->list.head.prev = &dispatcher->list.head;
}
