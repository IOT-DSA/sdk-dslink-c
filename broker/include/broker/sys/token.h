#ifndef BROKER_SYS_TOKEN_H
#define BROKER_SYS_TOKEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

int init_tokens(BrokerNode *sysNode);

BrokerNode *get_token_node(const char *hashedToken, const char *dsId);

void token_used(BrokerNode *tokenNode);

#ifdef __cplusplus
}
#endif

#endif // BROKER_SYS_TOKEN_H
