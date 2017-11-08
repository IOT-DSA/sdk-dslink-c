#include "broker/broker.h"

int main(int argc, char** argv) {
    if(argc == 2 && strcmp("--version", argv[1]) == 0) {
        printf("IOT-DSA c-broker version: %s\n", IOT_DSA_C_SDK_VERSION);
        return 0;
    }
    return broker_start();
}
