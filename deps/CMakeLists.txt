set(LIBUV_DIR "${CMAKE_CURRENT_LIST_DIR}/libuv")
set(LIBUV_SRC_DIR "${LIBUV_DIR}/src")
include_directories("${LIBUV_DIR}/include" "${LIBUV_SRC_DIR}")

set(LIBUV_SRC
    "${LIBUV_SRC_DIR}/fs-poll.c"
    "${LIBUV_SRC_DIR}/inet.c"
    "${LIBUV_SRC_DIR}/threadpool.c"
    "${LIBUV_SRC_DIR}/uv-common.c"
    "${LIBUV_SRC_DIR}/version.c"
)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600 -D_CRT_SECURE_NO_WARNINGS)
    include_directories(${LIBUV_SRC_DIR}/win)
    set(LIBUV_SRC "${LIBUV_SRC}"
        "${LIBUV_SRC_DIR}/async.c"
        "${LIBUV_SRC_DIR}/core.c"
        "${LIBUV_SRC_DIR}/dl.c"
        "${LIBUV_SRC_DIR}/error.c"
        "${LIBUV_SRC_DIR}/fs-event.c"
        "${LIBUV_SRC_DIR}/fs.c"
        "${LIBUV_SRC_DIR}/getaddrinfo.c"
        "${LIBUV_SRC_DIR}/getnameinfo.c"
        "${LIBUV_SRC_DIR}/handle.c"
        "${LIBUV_SRC_DIR}/loop-watcher.c"
        "${LIBUV_SRC_DIR}/pipe.c"
        "${LIBUV_SRC_DIR}/poll.c"
        "${LIBUV_SRC_DIR}/process-stdio.c"
        "${LIBUV_SRC_DIR}/process.c"
        "${LIBUV_SRC_DIR}/req.c"
        "${LIBUV_SRC_DIR}/signal.c"
        "${LIBUV_SRC_DIR}/snprintf.c"
        "${LIBUV_SRC_DIR}/stream.c"
        "${LIBUV_SRC_DIR}/tcp.c"
        "${LIBUV_SRC_DIR}/thread.c"
        "${LIBUV_SRC_DIR}/timer.c"
        "${LIBUV_SRC_DIR}/tty.c"
        "${LIBUV_SRC_DIR}/udp.c"
        "${LIBUV_SRC_DIR}/util.c"
        "${LIBUV_SRC_DIR}/winapi.c"
        "${LIBUV_SRC_DIR}/winsock.c"
    )
else()
    include_directories(${LIBUV_SRC_DIR}/unix)
    set(LIBUV_SRC "${LIBUV_SRC}"
        "${LIBUV_SRC_DIR}/unix/async.c"
        "${LIBUV_SRC_DIR}/unix/core.c"
        "${LIBUV_SRC_DIR}/unix/dl.c"
        "${LIBUV_SRC_DIR}/unix/fs.c"
        "${LIBUV_SRC_DIR}/unix/getaddrinfo.c"
        "${LIBUV_SRC_DIR}/unix/getnameinfo.c"
        "${LIBUV_SRC_DIR}/unix/loop-watcher.c"
        "${LIBUV_SRC_DIR}/unix/loop.c"
        "${LIBUV_SRC_DIR}/unix/pipe.c"
        "${LIBUV_SRC_DIR}/unix/poll.c"
        "${LIBUV_SRC_DIR}/unix/process.c"
        "${LIBUV_SRC_DIR}/unix/signal.c"
        "${LIBUV_SRC_DIR}/unix/stream.c"
        "${LIBUV_SRC_DIR}/unix/tcp.c"
        "${LIBUV_SRC_DIR}/unix/thread.c"
        "${LIBUV_SRC_DIR}/unix/timer.c"
        "${LIBUV_SRC_DIR}/unix/tty.c"
        "${LIBUV_SRC_DIR}/unix/udp.c"
    )

    if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        set(LIBUV_SRC "${LIBUV_SRC}"
            "${LIBUV_SRC_DIR}/unix/linux-core.c"
            "${LIBUV_SRC_DIR}/unix/linux-inotify.c"
            "${LIBUV_SRC_DIR}/unix/linux-syscalls.c"
            "${LIBUV_SRC_DIR}/unix/proctitle.c"
        )
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
        add_definitions(-D_DARWIN_USE_64_BIT_INODE=1 -D_DARWIN_UNLIMITED_SELECT=1)
        set(LIBUV_SRC "${LIBUV_SRC}"
            "${LIBUV_SRC_DIR}/unix/darwin.c"
            "${LIBUV_SRC_DIR}/unix/darwin-proctitle.c"
            "${LIBUV_SRC_DIR}/unix/fsevents.c"
            "${LIBUV_SRC_DIR}/unix/kqueue.c"
            "${LIBUV_SRC_DIR}/unix/proctitle.c"
            "${LIBUV_SRC_DIR}/unix/pthread-barrier.c"
        )
    endif()
endif()

add_library(libuv STATIC ${LIBUV_SRC})
target_compile_options(libuv PRIVATE "-fno-strict-aliasing" "-Wno-unused-parameter")
target_compile_options(libuv PRIVATE "-Wno-implicit-function-declaration")
export(TARGETS libuv
       FILE "${PROJECT_BINARY_DIR}/libuv-targets.cmake")
export(PACKAGE libuv)


set(MBED_DIR "${CMAKE_CURRENT_LIST_DIR}/mbedtls")
include_directories("${MBED_DIR}/include")

set(MBED_SRC_DIR "${MBED_DIR}/library")
set(MBED_SRC_CRYPTO
    "${MBED_SRC_DIR}/aes.c"
    "${MBED_SRC_DIR}/aesni.c"
    "${MBED_SRC_DIR}/arc4.c"
    "${MBED_SRC_DIR}/asn1parse.c"
    "${MBED_SRC_DIR}/asn1write.c"
    "${MBED_SRC_DIR}/base64.c"
    "${MBED_SRC_DIR}/bignum.c"
    "${MBED_SRC_DIR}/blowfish.c"
    "${MBED_SRC_DIR}/camellia.c"
    "${MBED_SRC_DIR}/ccm.c"
    "${MBED_SRC_DIR}/cipher.c"
    "${MBED_SRC_DIR}/cipher_wrap.c"
    "${MBED_SRC_DIR}/ctr_drbg.c"
    "${MBED_SRC_DIR}/des.c"
    "${MBED_SRC_DIR}/dhm.c"
    "${MBED_SRC_DIR}/ecdh.c"
    "${MBED_SRC_DIR}/ecdsa.c"
    #"${MBED_SRC_DIR}/ecjpake.c"
    "${MBED_SRC_DIR}/ecp.c"
    "${MBED_SRC_DIR}/ecp_curves.c"
    "${MBED_SRC_DIR}/entropy.c"
    "${MBED_SRC_DIR}/entropy_poll.c"
    "${MBED_SRC_DIR}/error.c"
    "${MBED_SRC_DIR}/gcm.c"
    #"${MBED_SRC_DIR}/havege.c"
    "${MBED_SRC_DIR}/hmac_drbg.c"
    "${MBED_SRC_DIR}/md.c"
    #"${MBED_SRC_DIR}/md2.c"
    #"${MBED_SRC_DIR}/md4.c"
    "${MBED_SRC_DIR}/md5.c"
    "${MBED_SRC_DIR}/md_wrap.c"
    #"${MBED_SRC_DIR}/memory_buffer_alloc.c"
    "${MBED_SRC_DIR}/oid.c"
    "${MBED_SRC_DIR}/padlock.c"
    "${MBED_SRC_DIR}/pem.c"
    "${MBED_SRC_DIR}/pk.c"
    "${MBED_SRC_DIR}/pk_wrap.c"
    "${MBED_SRC_DIR}/pkcs12.c"
    "${MBED_SRC_DIR}/pkcs5.c"
    "${MBED_SRC_DIR}/pkparse.c"
    "${MBED_SRC_DIR}/pkwrite.c"
    "${MBED_SRC_DIR}/platform.c"
    "${MBED_SRC_DIR}/ripemd160.c"
    "${MBED_SRC_DIR}/rsa.c"
    "${MBED_SRC_DIR}/sha1.c"
    "${MBED_SRC_DIR}/sha256.c"
    "${MBED_SRC_DIR}/sha512.c"
    #"${MBED_SRC_DIR}/threading.c"
    "${MBED_SRC_DIR}/timing.c"
    "${MBED_SRC_DIR}/version.c"
    "${MBED_SRC_DIR}/version_features.c"
    "${MBED_SRC_DIR}/xtea.c"
)

set(MBED_SRC_X509
    "${MBED_SRC_DIR}/certs.c"
    #"${MBED_SRC_DIR}/pkcs11.c"
    "${MBED_SRC_DIR}/x509.c"
    "${MBED_SRC_DIR}/x509_create.c"
    "${MBED_SRC_DIR}/x509_crl.c"
    "${MBED_SRC_DIR}/x509_crt.c"
    "${MBED_SRC_DIR}/x509_csr.c"
    "${MBED_SRC_DIR}/x509write_crt.c"
    "${MBED_SRC_DIR}/x509write_csr.c"
)

set(MBED_SRC_TLS
    "${MBED_SRC_DIR}/debug.c"
    "${MBED_SRC_DIR}/net.c"
    "${MBED_SRC_DIR}/ssl_cache.c"
    "${MBED_SRC_DIR}/ssl_ciphersuites.c"
    "${MBED_SRC_DIR}/ssl_cli.c"
    "${MBED_SRC_DIR}/ssl_cookie.c"
    "${MBED_SRC_DIR}/ssl_srv.c"
    "${MBED_SRC_DIR}/ssl_ticket.c"
    "${MBED_SRC_DIR}/ssl_tls.c"
)

set(MBED_SRC
    "${MBED_SRC_CRYPTO}"
    "${MBED_SRC_X509}"
    "${MBED_SRC_TLS}"
)

