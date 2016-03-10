//
// Created by rinick on 09/03/16.
//

#ifndef SDK_DSLINK_C_TOKEN_H
#define SDK_DSLINK_C_TOKEN_H


#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

int init_tokens(BrokerNode *sysNode);

BrokerNode *getTokenNode(const char *hashedToken, const char *dsId);

#ifdef __cplusplus
}
#endif


#endif //SDK_DSLINK_C_TOKEN_H
