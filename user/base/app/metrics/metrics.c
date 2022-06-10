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

#define TLOG_TAG "metrics"

#include "metrics.h"

#include <assert.h>
#include <interface/metrics/metrics.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <stdlib.h>
#include <trusty_log.h>
#include <uapi/err.h>

static int on_connect(const struct tipc_port* port,
                      handle_t chan,
                      const struct uuid* peer,
                      void** ctx_p) {
    struct srv_state* state = get_srv_state(port);
    assert(state->client_chan == INVALID_IPC_HANDLE);
    state->client_chan = chan;

    *ctx_p = state;
    return NO_ERROR;
}

static void on_channel_cleanup(void* ctx) {
    struct srv_state* state = (struct srv_state*)ctx;
    state->client_chan = INVALID_IPC_HANDLE;
}

static int on_message(const struct tipc_port* port, handle_t chan, void* _ctx) {
    /* In metrics TIPC protocol TA initiates the first message. */
    return ERR_BAD_STATE;
}

int add_metrics_service(struct srv_state* state) {
    static struct tipc_port_acl port_acl = {
            .flags = IPC_PORT_ALLOW_NS_CONNECT,
    };
    static struct tipc_port port = {
            .name = METRICS_PORT,
            .msg_max_size = METRICS_MAX_MSG_SIZE,
            .msg_queue_len = 1,
            .acl = &port_acl,
    };
    static struct tipc_srv_ops ops = {
            .on_connect = on_connect,
            .on_message = on_message,
            .on_channel_cleanup = on_channel_cleanup,
    };

    set_srv_state(&port, state);

    return tipc_add_service(state->hset, &port, 1, 1, &ops);
}
