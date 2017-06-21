#ifndef EIP_RESPONDER_REPLICATOR_H
#define EIP_RESPONDER_REPLICATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/dslink.h>
#include <dslink/node.h>

void eip_responder_init(DSLink *link, DSNode *root);

#ifdef __cplusplus
}
#endif

#endif // EIP_RESPONDER_REPLICATOR_H
