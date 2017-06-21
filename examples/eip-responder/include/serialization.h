#ifndef RESPONDER_SERIALIZATION_H
#define RESPONDER_SERIALIZATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/dslink.h>
#include <dslink/node.h>

void responder_init_serialization(DSLink *link, DSNode *root);

#ifdef __cplusplus
}
#endif

#endif // RESPONDER_SERIALIZATION_H
