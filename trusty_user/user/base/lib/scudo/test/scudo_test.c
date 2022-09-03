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

#include <lib/tipc/tipc.h>
#include <lib/unittest/unittest.h>
#include <trusty_unittest.h>
#include <uapi/err.h>

#include <scudo_app.h>
#include <scudo_consts.h>

#define TLOG_TAG "scudo_test"

/*
 * Sends command to app and then waits for a
 * reply or channel close. In the non-crashing case, the server
 * should echo back the original command and scudo_srv_rpc returns
 * NO_ERROR.
 */
static int scudo_srv_rpc(handle_t chan, enum scudo_command cmd) {
    int ret;
    struct scudo_msg msg = {
            .cmd = cmd,
    };

    ret = tipc_send1(chan, &msg, sizeof(msg));
    ASSERT_GE(ret, 0);
    ASSERT_EQ(ret, sizeof(msg));

    struct uevent evt;
    ret = wait(chan, &evt, INFINITE_TIME);
    if (ret) {
        /* error while waiting on channel */
        return ret;
    }

    if (evt.event & IPC_HANDLE_POLL_HUP) {
        ASSERT_EQ(evt.event & IPC_HANDLE_POLL_MSG, 0);
        return ERR_CHANNEL_CLOSED;
    }
    ASSERT_NE(evt.event & IPC_HANDLE_POLL_MSG, 0);

    ret = tipc_recv1(chan, sizeof(msg), &msg, sizeof(msg));
    if (ret < 0) {
        return ret;
    }
    ASSERT_EQ(ret, sizeof(msg));
    ASSERT_EQ(msg.cmd, cmd);

    return NO_ERROR;

test_abort:
    /* Use ERR_IO to indicate internal error with the test app */
    return ERR_IO;
}

typedef struct scudo_info {
    handle_t chan;
} scudo_info_t;

TEST_F_SETUP(scudo_info) {
    _state->chan = INVALID_IPC_HANDLE;
    ASSERT_EQ(tipc_connect(&_state->chan, SCUDO_TEST_SRV_PORT), 0);

test_abort:;
}

TEST_F_TEARDOWN(scudo_info) {
    close(_state->chan);
}

TEST_F(scudo_info, nop) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_NOP), NO_ERROR);
}

TEST_F(scudo_info, one_malloc) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_ONE_MALLOC), NO_ERROR);
}

TEST_F(scudo_info, one_calloc) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_ONE_CALLOC), NO_ERROR);
}

TEST_F(scudo_info, one_realloc) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_ONE_REALLOC), NO_ERROR);
}

TEST_F(scudo_info, many_malloc) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_MANY_MALLOC), NO_ERROR);
}

TEST_F(scudo_info, one_new) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_ONE_NEW), NO_ERROR);
}

TEST_F(scudo_info, one_new_arr) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_ONE_NEW_ARR), NO_ERROR);
}

TEST_F(scudo_info, malloc_and_new) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_MALLOC_AND_NEW), NO_ERROR);
}

TEST_F(scudo_info, double_free) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_DOUBLE_FREE),
              ERR_CHANNEL_CLOSED);
}

TEST_F(scudo_info, realloc_after_free) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_REALLOC_AFTER_FREE),
              ERR_CHANNEL_CLOSED);
}

TEST_F(scudo_info, dealloc_type_mismatch) {
    EXPECT_EQ(scudo_srv_rpc(_state->chan, SCUDO_DEALLOC_TYPE_MISMATCH),
              ERR_CHANNEL_CLOSED);
}

PORT_TEST(scudo_info, "com.android.trusty.scudotest")
