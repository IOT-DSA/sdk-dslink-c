set(LIBUV_DIR "${CMAKE_CURRENT_LIST_DIR}")
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
        )
    endif()
endif()

add_library(libuv STATIC ${LIBUV_SRC})
target_compile_options(libuv PRIVATE "-fno-strict-aliasing" "-Wno-unused-parameter")
target_compile_options(libuv PRIVATE "-Wno-implicit-function-declaration")
export(TARGETS libuv
       FILE "${PROJECT_BINARY_DIR}/libuv-targets.cmake")
export(PACKAGE libuv)
