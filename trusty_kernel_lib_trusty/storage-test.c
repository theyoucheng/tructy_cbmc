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

//#include <lib/storage/storage.h>
#include "/home/syc/workspace/google-aspire/trusty/trusty/user/base/lib/storage/include/lib/storage/storage.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
//#include <trusty_ipc.h>
#include "include/lib/trusty/ipc.h"
//#include <trusty_log.h>
//#include <uapi/err.h>
#include "/home/syc/workspace/google-aspire/trusty/external/lk/include/uapi/uapi/err.h"
#include "cbmc_trusty_header.h"

#define TLOG_TAG "storagetest-app"
#define TEST_CTRL_PORT "com.android.trusty.storagetest"

static const char* kFilePath = "storage_test_file";

static int write_file(size_t size) {
    uint8_t data[1024];

    if (size > sizeof(data)) {
        size = sizeof(data);
    }

//    //TLOGI("writing size %zu\n", size);
    storage_session_t session;
    int rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("couldn't open storage session\n");
        return -1;
    }

    file_handle_t handle;
    rc = storage_open_file(
            session, &handle, kFilePath,
            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE, 0);

    if (rc < 0) {
        __CPROVER_assert(0, "failed to create file");
        TLOGE("failed to create file: %d\n", rc);
        goto error;
    }

    memset(data, 0, size);
    rc = storage_write(handle, 0, data, size, STORAGE_OP_COMPLETE);
    //////storage_close_file(handle);

    __CPROVER_assert(0, "reachability condition in write_file .....................................................................................................................................................................................................");

error:
//    storage_close_session(session);
    return 0;
}

int main(void) {
    int rc;
    handle_t hport;
    uuid_t peer_uuid;

    TLOGI("Starting storage test app!!!\n");


    /* create control port and wait on it */
    //rc = sys_port_create(TEST_CTRL_PORT, 1, 1024, IPC_PORT_ALLOW_NS_CONNECT);
    //const char* port_name = TEST_CTRL_PORT;
    //__CPROVER_assume(port_name!=NULL);
    //int port_name_size = sizeof(port_name);
    //char c0 = port_name[0];
    //char c1 = port_name[1];
    //char c2 = port_name[2];
    //char c3 = port_name[3];
    //char c4 = port_name[4];
    //char c5 = port_name[5];
    //char c6 = port_name[6];
    //char c7 = port_name[7];
    //char c8 = port_name[8];
    //__CPROVER_havoc_object(port_name);
    int cbmc_port_len; 
    __CPROVER_assume(cbmc_port_len>=0);
    char cbmc_port_name[cbmc_port_len];
    int rc2 = sys_port_create(cbmc_port_name, 1, 1024, IPC_PORT_ALLOW_NS_CONNECT);
    
    //__CPROVER_assert(rc >= 0, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ret >= 0");
    //__CPROVER_assert(rc != rc2, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> rc!=rc2");
    //__CPROVER_assert(0, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> reachability test");
    //__CPROVER_assert(10 == rc2, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> rc!=rc2");

    if (rc < 0) {
        TLOGE("failed (%d) to create ctrl port\n", rc);
        return rc;
    }
//    hport = (handle_t)rc;
//
//    /* and just wait forever on control port  */
//    for (;;) {
//        uevent_t uevt;
//        int rc = wait(hport, &uevt, INFINITE_TIME);
//        if (rc == NO_ERROR) {
//            if (uevt.event & IPC_HANDLE_POLL_READY) {
//                /* got connection request */
//                rc = accept(uevt.handle, &peer_uuid);
//                if (rc >= 0) {
//                    handle_t ctrl_chan = (handle_t)rc;
//
//                    for (;;) {
//                        rc = write_file(256);
//__CPROVER_assert(0, "############## reachability condition 4 in main");
//                        if (rc < 0)
//                            break;
//
//                        rc = wait(ctrl_chan, &uevt, 0);
//                        if (rc == ERR_CHANNEL_CLOSED) {
//                            TLOGD("channel closed\n");
//                            break;
//                        }
//                        if (uevt.event & IPC_HANDLE_POLL_HUP) {
//                            TLOGD("POLL_HUP\n");
//                            break;
//                        }
//                    }
//                    close(ctrl_chan);
//                    continue;
//                } else {
//                    TLOGE("accept() failed\n");
//                }
//            }
//        }
//        if (rc < 0)
//            break;
//    }
//    TLOGD("exiting with exit code %d\n", rc);
    return rc;
}
