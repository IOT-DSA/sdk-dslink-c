#include <stdlib.h>
#include <string.h>
#include "dslink/col/list.h"

void list_init(List *list) {
    memset(list, 0, sizeof(List));
    list->head.next = &list->head;
    list->head.prev = &list->head;
}


ListNode *dslink_list_insert(List *list, void *data) {
    ListNode *node = malloc(sizeof(ListNode));
    if (!node) {
        return NULL;
    }

    insert_list_node(list, node);
    node->value = data;
    return node;
}

