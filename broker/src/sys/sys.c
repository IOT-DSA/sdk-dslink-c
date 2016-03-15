#include "broker/sys/sys.h"
#include "broker/sys/token.h"
#include "broker/sys/restart.h"
#include "broker/query/query.h"

int broker_sys_node_populate(BrokerNode *sysNode) {
    if (!sysNode) {
        return 1;
    }

    broker_query_create_action(sysNode);
    init_tokens(sysNode);
    init_restart(sysNode);
    return 0;
}
