#include "cmocka_init.h"

#include <stdint.h>

#include <dslink/socket.h>
#include <dslink/err.h>
#include <dslink/socket_private.h>

#include <uv-common.h>


static
void socket_init_deinit_test(void **state) {
    (void) state;

    Socket *socket = dslink_socket_init(0);
    assert_non_null(socket);
    assert_int_not_equal(socket->fd, -1);

    assert_int_equal(socket->addr.sin_family, AF_INET);
    assert_int_equal(socket->secure, 0);

    dslink_socket_close(&socket);
    assert_null(socket);

    Socket *ssl_socket = dslink_socket_init(1);
    assert_non_null(ssl_socket);
    assert_int_not_equal(ssl_socket->fd, -1);

    assert_int_equal(ssl_socket->addr.sin_family, AF_INET);
    assert_int_equal(ssl_socket->secure, 1);

    assert_non_null(ssl_socket->ssl_ctx);

    dslink_socket_close(&ssl_socket);
    assert_null(ssl_socket);
}


static uv_barrier_t server_ready_blocker;
static uv_barrier_t connection_ok_blocker;

static void server_basic(Socket *socket) {
    assert_function_success(dslink_socket_bind(socket, "0.0.0.0", 8189));

    dslink_socket_set_block(socket);

    uv_barrier_wait(&server_ready_blocker);

    Socket *client_socket = NULL;
    dslink_socket_accept(socket, &client_socket);
    uv_barrier_wait(&connection_ok_blocker);

    char rec_message[256];

    int byte_count = dslink_socket_read(client_socket, rec_message, 256);

    printf("Received Message =%d %s\n", byte_count, rec_message );

    dslink_socket_close(&client_socket);
}

static void client_basic(Socket *socket){
    (void) socket;

    uv_barrier_wait(&server_ready_blocker);

    dslink_socket_connect(&socket, "0.0.0.0", 8189, 0);
    uv_barrier_wait(&connection_ok_blocker);

    puts("It is Alive Client!!!!");

    char* message = "Hello World!";

    //try_count = 1;

    while(dslink_socket_write(socket, message, strlen(message)) < 0)
    {
        puts("Writing");
        sleep(1);
    };


    puts("Written");

}


static
void socket_bind_connect_test(void **state) {
    (void) state;

    Socket *server_socket = dslink_socket_init(0);
    assert_non_null(server_socket);

    Socket *client_socket = dslink_socket_init(0);

    uv_thread_t server_id;
    uv_thread_t client_id;

    uv_barrier_init(&server_ready_blocker, 2);
    uv_barrier_init(&connection_ok_blocker, 2);

    uv_thread_create(&server_id, (void (*)(void*)) server_basic, server_socket);
    uv_thread_create(&client_id, (void (*)(void*)) client_basic, client_socket);

    uv_thread_join(&client_id);
    uv_thread_join(&server_id);

    uv_barrier_destroy(&server_ready_blocker);
    uv_barrier_destroy(&connection_ok_blocker);

    dslink_socket_close(&server_socket);
    assert_null(server_socket);

    dslink_socket_close(&client_socket);
    assert_null(client_socket);

}


int main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(socket_init_deinit_test),
            cmocka_unit_test(socket_bind_connect_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
