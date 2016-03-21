#define LOG_TAG "main"

#include <dslink/log.h>
#include "replicator.h"
#include "rng.h"
#include "invoke.h"

void init(DSLink *link) {
    DSNode *superRoot = link->responder->super_root;

    responder_init_replicator(link, superRoot);
    responder_init_rng(link, superRoot);
    responder_init_invoke(link, superRoot);

    log_info("Initialized!\n");
}

void connected(DSLink *link) {
    (void) link;
    log_info("Connected!\n");
}

void disconnected(DSLink *link) {
    (void) link;
    log_info("Disconnected!\n");
}

int main(int argc, char **argv) {
    DSLinkCallbacks cbs = {
        init,
        connected,
        disconnected
    };

    return dslink_init(argc, argv, "C-Resp", 0, 1, &cbs);
}
