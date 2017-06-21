#ifndef RESPONDER_RNG_H
#define RESPONDER_RNG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/dslink.h>
#include <dslink/node.h>

void responder_init_rng(DSLink *link, DSNode *root);

#ifdef __cplusplus
}
#endif

#endif // RESPONDER_RNG_H
