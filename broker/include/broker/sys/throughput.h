#ifndef BROKER_THROUGHPUT_H
#define BROKER_THROUGHPUT_H

#ifdef __cplusplus
extern "C" {
#endif

struct BrokerNode;

int init_throughput(struct BrokerNode *sysNode);

int throughput_input_needed();
void throughput_add_input(int bytes, int messages);

int throughput_output_needed();
void throughput_add_output(int bytes, int messages);

#ifdef __cplusplus
}
#endif


#endif //BROKER_THROUGHPUT_H
