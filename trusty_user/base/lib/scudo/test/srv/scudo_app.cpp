/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TLOG_TAG "scudo_app"

#include <assert.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_log.h>
#include <uapi/err.h>

#include <scudo_app.h>
#include <scudo_consts.h>

#define ARR_SIZE 10

/*
 * Scudo supports dealloc type mismatch checking. That is, Scudo
 * can be configured to report an error if a chunk is allocated
 * using new but deallocated using free instead of delete, for
 * example. By default, dealloc type mismatch is disabled, but we
 * enable it here to check its functionality in
 * SCUDO_DEALLOC_TYPE_MISMATCH and also to ensure default Scudo
 * options can be overridden.
 */
extern "C" __attribute__((visibility("default"))) const char*
__scudo_default_options() {
    return "dealloc_type_mismatch=true";
}

static int scudo_on_message(const struct tipc_port* port,
                            handle_t chan,
                            void* ctx);

static struct tipc_port_acl scudo_port_acl = {
        .flags = IPC_PORT_ALLOW_TA_CONNECT,
        .uuid_num = 0,
        .uuids = NULL,
        .extra_data = NULL,
};

static struct tipc_port scudo_port = {
        .name = SCUDO_TEST_SRV_PORT,
        .msg_max_size = sizeof(struct scudo_msg),
        .msg_queue_len = 1,
        .acl = &scudo_port_acl,
        .priv = NULL,
};

/*
 * To make sure the variable isn't optimized away.
 */
static void touch(volatile void* a) {
    *(reinterpret_cast<volatile char*>(a)) =
            *(reinterpret_cast<volatile char*>(a));
}

/*
 * In addition to touching arr, it is memset with fill_char
 * and printed as a check that arr points to valid writable memory.
 */
static void touch_and_print(char* arr, const char fill_char) {
    touch(arr);
    memset(arr, fill_char, ARR_SIZE - 1);
    arr[ARR_SIZE - 1] = '\0';
    TLOG("arr = %s\n", arr);
}

static int scudo_on_message(const struct tipc_port* port,
                            handle_t chan,
                            void* ctx) {
    struct scudo_msg msg;

    int ret = tipc_recv1(chan, sizeof(msg), &msg, sizeof(msg));
    if (ret < 0 || ret != sizeof(msg)) {
        TLOGE("Failed to receive message (%d)\n", ret);
        return ret;
    }

    switch (msg.cmd) {
    /*
     * SCUDO_NOP test checks that the internal testing machinery
     * is working properly even when no Scudo functions are called.
     * Since some of the tests are expected to crash the server, we
     * need to make sure the server isn't just always crashing.
     */
    case SCUDO_NOP: {
        TLOGI("nop\n");
        break;
    }
    /*
     * SCUDO_ONE_MALLOC tests that a single call to malloc and free
     * works as intended.
     */
    case SCUDO_ONE_MALLOC: {
        TLOGI("one malloc\n");
        char* arr = reinterpret_cast<char*>(malloc(ARR_SIZE));
        touch_and_print(arr, 'a');
        free(arr);
        break;
    }
    /*
     * Similar to SCUDO_ONE_MALLOC, SCUDO_ONE_CALLOC tests that a
     * single call to calloc and free works as intended.
     */
    case SCUDO_ONE_CALLOC: {
        TLOGI("one calloc\n");
        char* arr = reinterpret_cast<char*>(calloc(ARR_SIZE, 1));
        touch_and_print(arr, 'a');
        free(arr);
        break;
    }
    /* Tests that a single call to realloc works. */
    case SCUDO_ONE_REALLOC: {
        TLOGI("one realloc\n");
        char* arr = reinterpret_cast<char*>(malloc(ARR_SIZE));
        touch_and_print(arr, 'a');
        arr = reinterpret_cast<char*>(realloc(arr, 2 * ARR_SIZE));
        touch_and_print(arr + ARR_SIZE - 1, 'b');
        TLOG("arr = %s\n", arr);
        free(arr);
        break;
    }
    /*
     * SCUDO_MANY_MALLOC performs a series of allocations and
     * deallocations to test (1) that deallocated chunks can be
     * reused, and (2) that Scudo can service various different
     * sizes of allocations requests. We know chunks are reused
     * because this app has 4096 bytes of heap memory and 5950
     * bytes are malloc-ed by SCUDO_MANY_MALLOC. Currently, Scudo
     * is configured with Trusty to have 128 byte chunks so the
     * largest malloc request that can be serviced is 112 bytes.
     */
    case SCUDO_MANY_MALLOC: {
        TLOGI("many malloc\n");
        for (int i = 0; i < 100; ++i) {
            char* arr = reinterpret_cast<char*>(malloc(ARR_SIZE + i));
            touch(arr);
            snprintf(arr, ARR_SIZE, "(%d)!", i);
            TLOG("arr = %s\n", arr);
            free(arr);
        }
        break;
    }
    /* Tests that a single allocation with new and delete works. */
    case SCUDO_ONE_NEW: {
        TLOGI("one new\n");
        int* foo = new int(37);
        touch(foo);
        TLOG("*foo = %d\n", *foo);
        delete foo;
        break;
    }
    /* Tests that a single allocation with new[] and delete[] works. */
    case SCUDO_ONE_NEW_ARR: {
        TLOGI("one new arr\n");
        char* arr = new char[ARR_SIZE];
        touch_and_print(arr, 'a');
        delete[] arr;
        break;
    }
    /* Tests that Scudo can service allocation requests using both malloc and
     * new. */
    case SCUDO_MALLOC_AND_NEW: {
        TLOGI("malloc and new\n");
        char* arr1 = reinterpret_cast<char*>(malloc(ARR_SIZE));
        touch_and_print(arr1, 'a');
        char* arr2 = new char[ARR_SIZE];
        touch_and_print(arr2, 'b');
        free(arr1);
        delete[] arr2;
        break;
    }
    /*
     * Scudo uses checksummed headers to protect against double-freeing,
     * so this test which attempts to free a chunk twice should crash.
     */
    case SCUDO_DOUBLE_FREE: {
        TLOGI("double free\n");
        char* arr = reinterpret_cast<char*>(malloc(ARR_SIZE));
        touch_and_print(arr, 'a');
        free(arr);
        free(arr);
        break;
    }
    /*
     * Scudo ensures that freed chunks cannot be realloc-ed, so this
     * test which attempts to realloc a freed chunk should crash.
     */
    case SCUDO_REALLOC_AFTER_FREE: {
        TLOGI("realloc after free\n");
        char* arr = reinterpret_cast<char*>(malloc(ARR_SIZE));
        touch_and_print(arr, 'a');
        free(arr);
        arr = reinterpret_cast<char*>(realloc(arr, 2 * ARR_SIZE));
        /* touch arr so realloc is not optimized away */
        touch(arr);
        break;
    }
    /*
     * When dealloc_type_mismatch is enabled, Scudo ensures that chunks
     * are allocated and deallocated using corresponding functions. Since
     * this test allocates a chunk with new and deallocates it with free,
     * it should crash the server.
     */
    case SCUDO_DEALLOC_TYPE_MISMATCH: {
        TLOGI("dealloc type mismatch\n");
        char* arr = new char[ARR_SIZE];
        touch_and_print(arr, 'a');
        free(arr);
        break;
    }
    default:
        TLOGE("Bad command: %d\n", msg.cmd);
        msg.cmd = SCUDO_BAD_CMD;
    }
    /*
     * We echo the incoming command in the case where the app
     * runs the test without crashing. This is effectively saying "did
     * not crash when executing command X."
     */
    ret = tipc_send1(chan, &msg, sizeof(msg));
    if (ret < 0 || ret != sizeof(msg)) {
        TLOGE("Failed to send message (%d)\n", ret);
        return ret < 0 ? ret : ERR_IO;
    }

    return 0;
}

static struct tipc_srv_ops scudo_ops = {
        .on_message = scudo_on_message,
};

int main(void) {
    struct tipc_hset* hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("Failed to create handle set (%d)\n", PTR_ERR(hset));
        return PTR_ERR(hset);
    }

    int rc = tipc_add_service(hset, &scudo_port, 1, 1, &scudo_ops);
    if (rc < 0) {
        TLOGE("Failed to add service (%d)\n", rc);
        return rc;
    }

    /* if app exits, kernel will log that */
    return tipc_run_event_loop(hset);
}
