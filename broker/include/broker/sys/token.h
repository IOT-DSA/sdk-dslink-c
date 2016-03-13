#ifndef BROKER_SYS_TOKEN_H
#define BROKER_SYS_TOKEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

int init_tokens(BrokerNode *sysNode);

BrokerNode *getTokenNode(const char *hashedToken, const char *dsId);

#ifdef __cplusplus
}
#endif

#endif // BROKER_SYS_TOKEN_H
