#ifndef SDK_DSLINK_C_LIST_H
#define SDK_DSLINK_C_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#define DSLINK_LIST_ITER(list) \
    for (ListNode *node = (list)->head; node != NULL; node = node->next)

typedef struct ListNode {
    struct ListNode *next;
    struct ListNode *prev;

    void *value;
} ListNode;

typedef struct List {
    struct ListNode *head;
    struct ListNode *tail;
} List;

void dslink_list_init(List *list);
ListNode *dslink_list_insert(List *list, void *data);
void dslink_list_insert_raw(List *list, ListNode *node);
void dslink_list_remove(List *list, ListNode *node);


#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_LIST_H
