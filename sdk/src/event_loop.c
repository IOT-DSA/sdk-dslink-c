#include <string.h>
#include <stdlib.h>
#include "dslink/event_loop.h"
#include "dslink/err.h"
#include "dslink/timer.h"

static
void dslink_event_loop_sched_raw(EventLoop *loop, EventTask *task) {
    if (!loop->head) {
        task->prev = NULL;
        task->next = NULL;
        loop->head = task;
        loop->tail = task;
        return;
    }

    if (task->delay >= loop->tail->delay) {
        // Insert at the end of the tail
        loop->tail->next = task;
        task->prev = loop->tail;
        task->next = NULL;
        loop->tail = task;
    } else {
        // Sort the event
        for (EventTask *t = loop->tail; t != NULL; t = t->prev) {
            if (t->delay <= task->delay) {
                task->next = t;
                task->prev = t->prev;
                if (t->prev == NULL) {
                    loop->head = task;
                } else {
                    t->prev->next = task;
                }
                t->prev = task;
                break;
            } else if (t == loop->head) {
                task->next = t;
                task->prev = NULL;
                loop->head->prev = task;
                loop->head = task;
                break;
            }
        }
    }

    return;
}

static
void dslink_event_loop_sub_del(EventLoop *loop, uint32_t delay) {
    for (EventTask *t = loop->head; t != NULL; t = t->next) {
        if (t->delay > delay) {
            t->delay -= delay;
        } else {
            t->delay = 0;
        }
    }
}

void dslink_event_loop_init(EventLoop *loop,
                            want_block_func func,
                            void *blockFuncData) {
    memset(loop, 0, sizeof(EventLoop));
    loop->block_func = func;
    loop->block_func_data = blockFuncData;
}

void dslink_event_loop_free(EventLoop *loop) {
    for (EventTask *task = loop->head; task != NULL;) {
        EventTask *tmp = task->next;
        free(task);
        task = tmp;
    }
}

int dslink_event_loop_sched(EventLoop *loop, task_func func, void *funcData) {
    return dslink_event_loop_schedd(loop, func, funcData, 0);
}

int dslink_event_loop_schedd(EventLoop *loop, task_func func,
                             void *funcData, uint32_t delay) {
    EventTask *task = malloc(sizeof(EventTask));
    if (!task) {
        return DSLINK_ALLOC_ERR;
    }
    task->delay = delay;
    task->func = func;
    task->func_data = funcData;
    dslink_event_loop_sched_raw(loop, task);
    return 0;
}

void dslink_event_loop_process(EventLoop *loop) {
    loop->shutdown = 0;
    while (!loop->head && loop->block_func) {
        loop->block_func(loop->block_func_data, loop, UINT32_MAX);
        if (loop->shutdown) {
            break;
        }
    }
loop_processor:
    while (!loop->shutdown && loop->head) {
        EventTask *task = loop->head;

        // Reconfigure the list
        loop->head = task->next;
        if (task == loop->tail) {
            loop->tail = loop->head;
        }
        if (loop->head) {
            loop->head->prev = NULL;
        }

        Timer timer;
        while (task->delay > 0) {
            dslink_timer_start(&timer);
            loop->block_func(loop->block_func_data,
                             loop, task->delay);
            uint32_t diff = dslink_timer_stop(&timer);
            if (task->delay > diff) {
                task->delay -= diff;
            } else {
                task->delay = 0;
            }
            dslink_event_loop_sub_del(loop, diff);
            if (loop->shutdown) {
                free(task);
                goto loop_processor;
            } else if (loop->head && (loop->head->delay < task->delay)) {
                dslink_event_loop_sched_raw(loop, task);
                goto loop_processor;
            }
        }

        dslink_timer_start(&timer);
        task->func(task->func_data, loop);
        task->delay += dslink_timer_stop(&timer);

        // Handle the delays of the next tasks
        dslink_event_loop_sub_del(loop, task->delay);

        free(task);
    }
}
