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

#define TLOG_TAG "metrics-consumer"

#include "metrics.h"

#include <interface/metrics/consumer.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <metrics_consts.h>
#include <string.h>
#include <trusty_log.h>
#include <uapi/err.h>

static int broadcast_event(handle_t chan,
                           uint32_t cmd,
                           uint8_t* msg,
                           size_t msg_len) {
    int rc;
    uevent_t evt;
    struct metrics_resp resp;

    if (chan == INVALID_IPC_HANDLE) {
        TLOGI("no metrics client connected\n");
        return NO_ERROR;
    }

    rc = tipc_send1(chan, msg, msg_len);
    if (rc < 0) {
        TLOGE("failed (%d) to send metrics event\n", rc);
        return rc;
    }

    if (rc != (int)msg_len) {
        TLOGE("unexpected number of bytes sent: %d\n", rc);
        return ERR_BAD_LEN;
    }

    rc = wait(chan, &evt, INFINITE_TIME);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to wait for response\n", rc);
        return rc;
    }

    rc = tipc_recv1(chan, sizeof(resp), &resp, sizeof(resp));
    if (rc < 0) {
        TLOGE("failed (%d) to receive metrics event response\n", rc);
        return rc;
    }

    if (rc != sizeof(resp)) {
        TLOGE("unexpected number of bytes received: %d\n", rc);
        return ERR_BAD_LEN;
    }

    if (resp.cmd != (cmd | METRICS_CMD_RESP_BIT)) {
        TLOGE("unknown command received: %d\n", rc);
        return ERR_CMD_UNKNOWN;
    }

    switch (resp.status) {
    case METRICS_NO_ERROR:
        break;
    case METRICS_ERR_UNKNOWN_CMD:
        TLOGE("client doesn't recognize the command: %d\n", cmd);
        break;
    default:
        TLOGE("unknown return code: %d\n", resp.status);
        return ERR_CMD_UNKNOWN;
    }

    return NO_ERROR;
}

static int on_message(const struct tipc_port* port, handle_t chan, void* ctx) {
    int rc;
    struct metrics_req req;
    struct metrics_resp resp;
    uint32_t cmd;
    uint8_t msg[METRICS_MAX_MSG_SIZE];
    size_t msg_len;
    struct srv_state* state = get_srv_state(port);

    memset(msg, 0, sizeof(msg));
    rc = tipc_recv1(chan, sizeof(req), msg, sizeof(msg));
    if (rc < 0) {
        TLOGE("failed (%d) to receive metrics event\n", rc);
        return rc;
    }
    msg_len = rc;
    cmd = ((struct metrics_req*)msg)->cmd;

    rc = broadcast_event(state->client_chan, cmd, msg, msg_len);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to broadcast metrics event to NS\n", rc);
    }

    resp.cmd = (cmd | METRICS_CMD_RESP_BIT);
    resp.status = METRICS_NO_ERROR;
    rc = tipc_send1(chan, &resp, sizeof(resp));
    if (rc < 0) {
        TLOGE("failed (%d) to send metrics event response\n", rc);
        return rc;
    }

    if (rc != sizeof(resp)) {
        TLOGE("unexpected number of bytes sent: %d\n", rc);
        return ERR_BAD_LEN;
    }

    return NO_ERROR;
}

int add_metrics_consumer_service(struct srv_state* state) {
    static const struct uuid kernel_uuid = UUID_KERNEL_VALUE;
    static const struct uuid* allowed_uuids[] = {
            &kernel_uuid,
    };
    static struct tipc_port_acl port_acl = {
            .flags = IPC_PORT_ALLOW_TA_CONNECT,
            .uuids = allowed_uuids,
            .uuid_num = countof(allowed_uuids),
    };
    static struct tipc_port port = {
            .name = METRICS_CONSUMER_PORT,
            .msg_max_size = METRICS_MAX_MSG_SIZE,
            .msg_queue_len = 1,
            .acl = &port_acl,
    };
    static struct tipc_srv_ops ops = {
            .on_message = on_message,
    };

    set_srv_state(&port, state);

    return tipc_add_service(state->hset, &port, 1, 0, &ops);
}
