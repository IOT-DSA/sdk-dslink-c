#include "broker/sys/sys.h"
#include "broker/query/query.h"

int broker_sys_node_populate(BrokerNode *dataNode) {
    if (!dataNode) {
        return 1;
    }

    broker_query_create_action(dataNode);
    return 0;
}
