#ifndef RESPONDER_SEQUENCE_H
#define RESPONDER_SEQUENCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/dslink.h>
#include <dslink/node.h>

void responder_init_sequence(DSLink *link, DSNode *root);

#ifdef __cplusplus
}
#endif

#endif // RESPONDER_SEQUENCE_H
