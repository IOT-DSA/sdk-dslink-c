#include <stdlib.h>
#include <string.h>
#include "dslink/col/list.h"

void dslink_list_init(List *list) {
    memset(list, 0, sizeof(List));
}

void dslink_list_insert_raw(List *list, ListNode *node) {
    node->next = NULL;
    if (!list->head) {
        node->prev = NULL;
        list->head = node;
        list->tail = node;
        return;
    }

    node->prev = list->tail;
    list->tail->next = node;
    list->tail = node;
}

ListNode *dslink_list_insert(List *list, void *data) {
    ListNode *node = malloc(sizeof(ListNode));
    if (!node) {
        return NULL;
    }

    dslink_list_insert_raw(list, node);
    node->value = data;
    return node;
}

void dslink_list_remove(List *list, ListNode *node) {
    if (node->prev) {
        node->prev->next = node->next;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }
    if (list->head == node) {
        list->head = node->next;
    }
    if (list->tail == node) {
        list->tail = node->prev;
    }
    free(node);
}
