/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define TLOG_TAG "secure_fb_test"

#include <lib/secure_fb/secure_fb.h>
#include <trusty_unittest.h>
#include <uapi/err.h>

typedef struct {
    secure_fb_handle_t session;
    struct secure_fb_info fb_info;
} secure_fb_t;

TEST_F_SETUP(secure_fb) {
    int rc;

    _state->session = 0;
    rc = secure_fb_open(&_state->session, &_state->fb_info, 0);
    ASSERT_EQ(rc, 0);

test_abort:;
}

TEST_F_TEARDOWN(secure_fb) {
    secure_fb_close(_state->session);
}

TEST_F(secure_fb, open_and_close) {
    /* Only need Setup() and Teardown() to run. */
}

TEST_F(secure_fb, fb_info) {
    struct secure_fb_info* fb_info = &_state->fb_info;

    ASSERT_NE(fb_info->buffer, NULL);
    ASSERT_GT(fb_info->size, 0);
    ASSERT_GT(fb_info->pixel_stride, 0);
    ASSERT_GT(fb_info->line_stride, 0);
    ASSERT_GT(fb_info->width, 0);
    ASSERT_GT(fb_info->width, 0);
    ASSERT_NE(fb_info->pixel_format, TTUI_PF_INVALID);

    ASSERT_LE(fb_info->width * fb_info->pixel_stride, fb_info->line_stride);
    ASSERT_LE(fb_info->height * fb_info->line_stride, fb_info->size);

test_abort:;
}

TEST_F(secure_fb, display) {
    int rc;
    struct secure_fb_info* fb_info = &_state->fb_info;

    /*
     * Set all pixel channels to max value. We only check that the operations
     * don't fail in this test. Checking that screen color is correct needs to
     * be done manually.
     */
    memset(fb_info->buffer, 0xff, fb_info->size);
    rc = secure_fb_display_next(_state->session, &_state->fb_info);
    ASSERT_EQ(rc, 0);

test_abort:;
}

TEST(secure_fb, stress) {
    int rc;
    secure_fb_handle_t session;
    struct secure_fb_info fb_info;

    for (size_t i = 0; i < 100; i++) {
        rc = secure_fb_open(&session, &fb_info, 0);
        ASSERT_EQ(rc, 0);
        secure_fb_close(session);
    }

test_abort:;
}

PORT_TEST(secure_fb, "com.android.trusty.secure_fb.test");
