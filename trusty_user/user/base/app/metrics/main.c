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

#define TLOG_TAG "metrics-srv"

#include "metrics.h"

#include <lib/tipc/tipc_srv.h>
#include <lk/err_ptr.h>
#include <trusty_log.h>

int main(void) {
    int rc;
    struct tipc_hset* hset;
    struct srv_state state;

    hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("failed (%d) to create handle set\n", PTR_ERR(hset));
        return PTR_ERR(hset);
    }

    state.client_chan = INVALID_IPC_HANDLE;
    state.hset = hset;

    rc = add_metrics_service(&state);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to add metrics service\n", rc);
        return rc;
    }

    rc = add_metrics_consumer_service(&state);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to add metrics consumer service\n", rc);
        return rc;
    }

    return tipc_run_event_loop(hset);
}
