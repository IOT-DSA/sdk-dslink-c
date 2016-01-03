#ifndef RESPONDER_REPLICATOR_H
#define RESPONDER_REPLICATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/dslink.h>
#include <dslink/node.h>

void responder_init_replicator(DSLink *link, DSNode *root);

#ifdef __cplusplus
}
#endif

#endif // RESPONDER_REPLICATOR_H
