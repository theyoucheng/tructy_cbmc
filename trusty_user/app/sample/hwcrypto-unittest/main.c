/*
 * Copyright (C) 2015 The Android Open Source Project
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

/*
 * Tests:
 * generic:
 * - no session / invalid session
 * - closed session
 *
 * hwkey:
 * - derive twice to same result
 * - derive different, different result
 * - keyslot, invalid slot
 *
 * rng:
 *
 */

#define TLOG_TAG "hwcrypto_unittest"

#include <stdlib.h>
#include <string.h>

#include <lib/hwkey/hwkey.h>
#include <lib/rng/trusty_rng.h>
#include <trusty_unittest.h>
#include <uapi/err.h>

#define RPMB_STORAGE_AUTH_KEY_ID "com.android.trusty.storage_auth.rpmb"
#define HWCRYPTO_UNITTEST_KEYBOX_ID "com.android.trusty.hwcrypto.unittest.key32"
#define HWCRYPTO_UNITTEST_DERIVED_KEYBOX_ID \
    "com.android.trusty.hwcrypto.unittest.derived_key32"
#define HWCRYPTO_UNITTEST_OPAQUE_HANDLE_ID \
    "com.android.trusty.hwcrypto.unittest.opaque_handle"
#define HWCRYPTO_UNITTEST_OPAQUE_HANDLE2_ID \
    "com.android.trusty.hwcrypto.unittest.opaque_handle2"
#define HWCRYPTO_UNITTEST_OPAQUE_HANDLE_NOACCESS_ID \
    "com.android.trusty.hwcrypto.unittest.opaque_handle_noaccess"
#define HWCRYPTO_UNITTEST_OPAQUE_DERIVED_ID \
    "com.android.trusty.hwcrypto.unittest.opaque_derived"

#define STORAGE_AUTH_KEY_SIZE 32

static const uint8_t UNITTEST_KEYSLOT[] = "unittestkeyslotunittestkeyslotun";
static const uint8_t UNITTEST_DERIVED_KEYSLOT[] =
        "unittestderivedkeyslotunittestde";

#if WITH_HWCRYPTO_UNITTEST
#define DISABLED_WITHOUT_HWCRYPTO_UNITTEST(name) name
#else
#pragma message                                                                          \
        "hwcrypto-unittest is built with the WITH_HWCRYPTO_UNITTEST define not enabled." \
        "Hwkey tests will not test anything."
#define DISABLED_WITHOUT_HWCRYPTO_UNITTEST(name) DISABLED_##name
#endif

/*
 * Implement this hook for device specific hwkey tests
 */
__WEAK void run_device_hwcrypto_unittest(void) {}

TEST(hwcrypto, device_hwcrypto_unittest) {
    run_device_hwcrypto_unittest();
}

typedef struct hwkey {
    hwkey_session_t hwkey_session;
} hwkey_t;

TEST_F_SETUP(hwkey) {
    int rc;

    _state->hwkey_session = INVALID_IPC_HANDLE;
    rc = hwkey_open();
    ASSERT_GE(rc, 0);
    _state->hwkey_session = (hwkey_session_t)rc;

test_abort:;
}

TEST_F_TEARDOWN(hwkey) {
    close(_state->hwkey_session);
}

TEST_F(hwkey, generic_invalid_session) {
    const uint8_t src_data[] = "thirtytwo-bytes-of-nonsense-data";
    static const size_t size = sizeof(src_data);
    uint8_t dest[sizeof(src_data)];

    hwkey_session_t invalid = INVALID_IPC_HANDLE;
    uint32_t kdf_version = HWKEY_KDF_VERSION_BEST;

    // should fail immediately
    long rc = hwkey_derive(invalid, &kdf_version, src_data, dest, size);
    EXPECT_EQ(ERR_BAD_HANDLE, rc, "generic - bad handle");
}

TEST_F(hwkey, generic_closed_session) {
    static const uint8_t src_data[] = "thirtytwo-bytes-of-nonsense-data";
    static const uint32_t size = sizeof(src_data);
    uint8_t dest[sizeof(src_data)];
    uint32_t kdf_version = HWKEY_KDF_VERSION_BEST;

    long rc = hwkey_open();
    EXPECT_GE(rc, 0, "generic - open");

    hwkey_session_t session = (hwkey_session_t)rc;
    hwkey_close(session);

    // should fail immediately
    rc = hwkey_derive(session, &kdf_version, src_data, dest, size);
    EXPECT_EQ(ERR_NOT_FOUND, rc, "generic - closed handle");
}

TEST_F(hwkey, derive_repeatable) {
    const uint8_t src_data[] = "thirtytwo-bytes-of-nonsense-data";
    uint8_t dest[32];
    uint8_t dest2[sizeof(dest)];
    static const size_t size = sizeof(dest);
    uint32_t kdf_version = HWKEY_KDF_VERSION_BEST;

    memset(dest, 0, size);
    memset(dest2, 0, size);

    /* derive key once */
    long rc = hwkey_derive(_state->hwkey_session, &kdf_version, src_data, dest,
                           size);
    EXPECT_EQ(NO_ERROR, rc, "derive repeatable - initial derivation");
    EXPECT_NE(HWKEY_KDF_VERSION_BEST, kdf_version,
              "derive repeatable - kdf version");

    /* derive key again */
    rc = hwkey_derive(_state->hwkey_session, &kdf_version, src_data, dest2,
                      size);
    EXPECT_EQ(NO_ERROR, rc, "derive repeatable - second derivation");

    /* ensure they are the same */
    rc = memcmp(dest, dest2, size);
    EXPECT_EQ(0, rc, "derive repeatable - equal");
    rc = memcmp(dest, src_data, size);
    EXPECT_NE(0, rc, "derive repeatable - same as seed");
}

TEST_F(hwkey, derive_different) {
    const uint8_t src_data[] = "thirtytwo-bytes-of-nonsense-data";
    const uint8_t src_data2[] = "thirtytwo-byt3s-of-nons3ns3-data";

    uint8_t dest[32];
    uint8_t dest2[sizeof(dest)];
    static const uint32_t size = sizeof(dest);
    uint32_t kdf_version = HWKEY_KDF_VERSION_BEST;

    memset(dest, 0, size);
    memset(dest2, 0, size);

    /* derive key once */
    long rc = hwkey_derive(_state->hwkey_session, &kdf_version, src_data, dest,
                           size);
    EXPECT_EQ(NO_ERROR, rc, "derive not repeatable - initial derivation");
    EXPECT_NE(HWKEY_KDF_VERSION_BEST, kdf_version,
              "derive not repeatable - kdf version");

    /* derive key again, with different source data */
    rc = hwkey_derive(_state->hwkey_session, &kdf_version, src_data2, dest2,
                      size);
    EXPECT_EQ(NO_ERROR, rc, "derive not repeatable - second derivation");

    /* ensure they are not the same */
    rc = memcmp(dest, dest2, size);
    EXPECT_NE(0, rc, "derive not repeatable - equal");
    rc = memcmp(dest, src_data, size);
    EXPECT_NE(0, rc, "derive not repeatable - equal to source");
    rc = memcmp(dest2, src_data2, size);
    EXPECT_NE(0, rc, "derive not repeatable - equal to source");
}

TEST_F(hwkey, derive_zero_length) {
    static const uint32_t size = 0;
    const uint8_t* src_data = NULL;
    uint8_t* dest = NULL;
    uint32_t kdf_version = HWKEY_KDF_VERSION_BEST;

    /* derive key once */
    long rc = hwkey_derive(_state->hwkey_session, &kdf_version, src_data, dest,
                           size);
    EXPECT_EQ(ERR_NOT_VALID, rc, "derive zero length");
}

TEST_F(hwkey, get_storage_auth) {
    uint32_t actual_size = STORAGE_AUTH_KEY_SIZE;
    uint8_t storage_auth_key[STORAGE_AUTH_KEY_SIZE];
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     RPMB_STORAGE_AUTH_KEY_ID, storage_auth_key,
                                     &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc, "auth key accessible when it shouldn't be");
}

TEST_F(hwkey, get_keybox) {
    uint8_t dest[sizeof(HWCRYPTO_UNITTEST_KEYBOX_ID)];
    uint32_t actual_size = sizeof(dest);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     HWCRYPTO_UNITTEST_KEYBOX_ID, dest,
                                     &actual_size);

#if WITH_HWCRYPTO_UNITTEST
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest keybox");
    rc = memcmp(UNITTEST_KEYSLOT, dest, sizeof(UNITTEST_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "get storage auth key invalid");
#else
    EXPECT_EQ(ERR_NOT_FOUND, rc, "get hwcrypto-unittest keybox");
#endif
}

/*
 * The derived key slot should return UNITTEST_DERIVED_KEYSLOT after decrypting
 * it with the UNITTEST_KEYSLOT key.
 */
TEST_F(hwkey, get_derived_keybox) {
    uint8_t dest[sizeof(UNITTEST_DERIVED_KEYSLOT) - 1];
    uint32_t actual_size = sizeof(dest);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     HWCRYPTO_UNITTEST_DERIVED_KEYBOX_ID, dest,
                                     &actual_size);

#if WITH_HWCRYPTO_UNITTEST
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest derived keybox");
    rc = memcmp(UNITTEST_DERIVED_KEYSLOT, dest,
                sizeof(UNITTEST_DERIVED_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "get derived invalid");
#else
    EXPECT_EQ(ERR_NOT_FOUND, rc, "get hwcrypto-unittest derived keybox");
#endif
}

TEST_F(hwkey, get_opaque_handle) {
    uint8_t dest[HWKEY_OPAQUE_HANDLE_MAX_SIZE] = {0};
    uint32_t actual_size = sizeof(dest);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     HWCRYPTO_UNITTEST_OPAQUE_HANDLE_ID, dest,
                                     &actual_size);
#if WITH_HWCRYPTO_UNITTEST
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque keybox");
    EXPECT_LE(actual_size, HWKEY_OPAQUE_HANDLE_MAX_SIZE);

    rc = strnlen((const char*)dest, HWKEY_OPAQUE_HANDLE_MAX_SIZE);
    EXPECT_LT(rc, HWKEY_OPAQUE_HANDLE_MAX_SIZE,
              "opaque handle is unexpected size");
#else
    EXPECT_EQ(ERR_NOT_FOUND, rc, "hwcrypto-unittest not enabled");
#endif
}

/* The following tests require hwcrpyto-unittest to do anything useful. */

TEST_F(hwkey, DISABLED_WITHOUT_HWCRYPTO_UNITTEST(get_opaque_key)) {
    uint8_t handle[HWKEY_OPAQUE_HANDLE_MAX_SIZE] = {0};
    uint32_t actual_size = sizeof(handle);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     HWCRYPTO_UNITTEST_OPAQUE_HANDLE_ID, handle,
                                     &actual_size);

    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque keybox");
    EXPECT_LE(actual_size, HWKEY_OPAQUE_HANDLE_MAX_SIZE);
    rc = strnlen((const char*)handle, HWKEY_OPAQUE_HANDLE_MAX_SIZE);
    EXPECT_LT(rc, HWKEY_OPAQUE_HANDLE_MAX_SIZE,
              "Unexpected opaque handle size");

    uint8_t key_buf[sizeof(UNITTEST_KEYSLOT) - 1] = {0};
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle,
                                key_buf, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque key failed");

    rc = memcmp(UNITTEST_KEYSLOT, key_buf, sizeof(UNITTEST_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "opaque key did not match expected value");
}

TEST_F(hwkey, DISABLED_WITHOUT_HWCRYPTO_UNITTEST(get_multiple_opaque_handles)) {
    uint8_t handle1[HWKEY_OPAQUE_HANDLE_MAX_SIZE] = {0};
    uint32_t actual_size = sizeof(handle1);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     HWCRYPTO_UNITTEST_OPAQUE_HANDLE_ID,
                                     handle1, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque keybox");
    EXPECT_LE(actual_size, HWKEY_OPAQUE_HANDLE_MAX_SIZE);

    uint8_t handle2[HWKEY_OPAQUE_HANDLE_MAX_SIZE] = {0};
    actual_size = sizeof(handle2);
    rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                HWCRYPTO_UNITTEST_OPAQUE_HANDLE_NOACCESS_ID,
                                handle2, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque keybox");
    EXPECT_LE(actual_size, HWKEY_OPAQUE_HANDLE_MAX_SIZE);

    rc = memcmp(handle1, handle2, HWKEY_OPAQUE_HANDLE_MAX_SIZE);
    EXPECT_NE(0, rc, "opaque handles should not be the same");

    uint8_t key_buf[sizeof(UNITTEST_KEYSLOT)] = {0};
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle1,
                                key_buf, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "handle was not valid");
    EXPECT_EQ(actual_size, sizeof(UNITTEST_KEYSLOT) - 1, "wrong key length");
    rc = memcmp(UNITTEST_KEYSLOT, key_buf, sizeof(UNITTEST_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "opaque key did not match expected value");

    /* we are not allowed to retrieve key material for the NOACCESS handle */
    memset(key_buf, 0, sizeof(UNITTEST_KEYSLOT));
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle2,
                                key_buf, &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc,
              "should not be able to retrieve key for second handle");

    /*
     * We need to reconnect to ensure that the tokens have been dropped and
     * cleared.
     */
    hwkey_close(_state->hwkey_session);
    int new_sess = hwkey_open();
    ASSERT_GE(new_sess, 0);
    _state->hwkey_session = (hwkey_session_t)new_sess;

    /* Has the keyslot data been cleared? */
    memset(key_buf, 0, sizeof(UNITTEST_KEYSLOT));
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle1,
                                key_buf, &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc, "handle was still valid");

    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle2,
                                key_buf, &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc, "handle was still valid");

test_abort:;
}

/*
 * Make sure that attempting to get the same handle from multiple concurrent
 * sessions doesn't break things.
 */
TEST_F(hwkey,
       DISABLED_WITHOUT_HWCRYPTO_UNITTEST(opaque_handle_multiple_sessions)) {
    uint8_t handle1[HWKEY_OPAQUE_HANDLE_MAX_SIZE] = {0};
    uint32_t actual_size = sizeof(handle1);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     HWCRYPTO_UNITTEST_OPAQUE_HANDLE_ID,
                                     handle1, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque keybox");
    EXPECT_LE(actual_size, HWKEY_OPAQUE_HANDLE_MAX_SIZE);

    int new_sess = hwkey_open();
    ASSERT_GE(new_sess, 0);

    uint8_t handle2[HWKEY_OPAQUE_HANDLE_MAX_SIZE] = {0};
    actual_size = sizeof(handle2);
    rc = hwkey_get_keyslot_data(new_sess, HWCRYPTO_UNITTEST_OPAQUE_HANDLE_ID,
                                handle2, &actual_size);
    EXPECT_EQ(ERR_ALREADY_EXISTS, rc, "retrieve same handle twice");

    /* Fetch a new handle with a different keyslot from the second session */
    actual_size = sizeof(handle2);
    rc = hwkey_get_keyslot_data(new_sess, HWCRYPTO_UNITTEST_OPAQUE_HANDLE2_ID,
                                handle2, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque keybox");
    EXPECT_LE(actual_size, HWKEY_OPAQUE_HANDLE_MAX_SIZE);

    uint8_t key_buf[sizeof(UNITTEST_KEYSLOT)] = {0};

    /* Fetch the keys via the first session */
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle1,
                                key_buf, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "handle was not valid");
    EXPECT_EQ(actual_size, sizeof(UNITTEST_KEYSLOT) - 1, "wrong key length");
    rc = memcmp(UNITTEST_KEYSLOT, key_buf, sizeof(UNITTEST_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "opaque key did not match expected value");

    memset(key_buf, 0, sizeof(UNITTEST_KEYSLOT));
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle2,
                                key_buf, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "handle was not valid");
    EXPECT_EQ(actual_size, sizeof(UNITTEST_KEYSLOT) - 1, "wrong key length");
    rc = memcmp(UNITTEST_KEYSLOT, key_buf, sizeof(UNITTEST_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "opaque key did not match expected value");

    /* Fetch the same key via the second session */
    memset(key_buf, 0, sizeof(UNITTEST_KEYSLOT));
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(new_sess, (const char*)handle1, key_buf,
                                &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "handle was not valid");
    EXPECT_EQ(actual_size, sizeof(UNITTEST_KEYSLOT) - 1, "wrong key length");
    rc = memcmp(UNITTEST_KEYSLOT, key_buf, sizeof(UNITTEST_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "opaque key did not match expected value");

    memset(key_buf, 0, sizeof(UNITTEST_KEYSLOT));
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(new_sess, (const char*)handle2, key_buf,
                                &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "handle was not valid");
    EXPECT_EQ(actual_size, sizeof(UNITTEST_KEYSLOT) - 1, "wrong key length");
    rc = memcmp(UNITTEST_KEYSLOT, key_buf, sizeof(UNITTEST_KEYSLOT) - 1);
    EXPECT_EQ(0, rc, "opaque key did not match expected value");

    hwkey_close(new_sess);

    /* Has the keyslot data been cleared? */
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle1,
                                key_buf, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "first session handle wasn't valid");

    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle2,
                                key_buf, &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc, "second session handle was still valid");

    /* Disconnect the original session which retrieved the handle */
    hwkey_close(_state->hwkey_session);
    new_sess = hwkey_open();
    ASSERT_GE(new_sess, 0);
    _state->hwkey_session = (hwkey_session_t)new_sess;

    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle1,
                                key_buf, &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc, "handle was still valid");

    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle2,
                                key_buf, &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc, "handle was still valid");

test_abort:;
}

TEST_F(hwkey, DISABLED_WITHOUT_HWCRYPTO_UNITTEST(try_empty_opaque_handle)) {
    /* Reconnect just to make sure there is no spurious handles remaining. */
    hwkey_close(_state->hwkey_session);
    int new_sess = hwkey_open();
    ASSERT_GE(new_sess, 0);
    _state->hwkey_session = (hwkey_session_t)new_sess;

    uint8_t key_buf[sizeof(UNITTEST_KEYSLOT) - 1] = {0};
    uint32_t actual_size = sizeof(key_buf);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session, "", key_buf,
                                     &actual_size);
    EXPECT_EQ(ERR_NOT_FOUND, rc,
              "retrieving a key with an empty access token succeeded");

test_abort:;
}

TEST_F(hwkey, DISABLED_WITHOUT_HWCRYPTO_UNITTEST(get_opaque_derived_key)) {
    uint8_t handle[HWKEY_OPAQUE_HANDLE_MAX_SIZE] = {0};
    uint32_t actual_size = sizeof(handle);
    long rc = hwkey_get_keyslot_data(_state->hwkey_session,
                                     HWCRYPTO_UNITTEST_OPAQUE_DERIVED_ID,
                                     handle, &actual_size);

    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest opaque derived key");
    EXPECT_LE(actual_size, HWKEY_OPAQUE_HANDLE_MAX_SIZE);
    rc = strnlen((const char*)handle, HWKEY_OPAQUE_HANDLE_MAX_SIZE);
    EXPECT_EQ(rc, actual_size - 1, "Unexpected opaque handle size");

    uint8_t key_buf[sizeof(UNITTEST_DERIVED_KEYSLOT) - 1];
    actual_size = sizeof(key_buf);
    rc = hwkey_get_keyslot_data(_state->hwkey_session, (const char*)handle,
                                key_buf, &actual_size);
    EXPECT_EQ(NO_ERROR, rc, "get hwcrypto-unittest derived key failed");
    EXPECT_EQ(actual_size, sizeof(key_buf), "Unexpected opaque handle size");

    rc = memcmp(UNITTEST_DERIVED_KEYSLOT, key_buf, sizeof(key_buf));
    EXPECT_EQ(0, rc, "get derived invalid");
}

/***********************   HWRNG  UNITTEST  ***********************/

static uint32_t _hist[256];
static uint8_t _rng_buf[1024];

static void hwrng_update_hist(uint8_t* data, unsigned int cnt) {
    for (unsigned int i = 0; i < cnt; i++) {
        _hist[data[i]]++;
    }
}

static void hwrng_show_data(const void* ptr, size_t len) {
    uintptr_t address = (uintptr_t)ptr;
    size_t count;
    size_t i;
    fprintf(stderr, "Dumping first hwrng request:\n");
    for (count = 0; count < len; count += 16) {
        for (i = 0; i < MIN(len - count, 16); i++) {
            fprintf(stderr, "0x%02hhx ", *(const uint8_t*)(address + i));
        }
        fprintf(stderr, "\n");
        address += 16;
    }
}

TEST(hwrng, show_data_test) {
    int rc;
    rc = trusty_rng_hw_rand(_rng_buf, 32);
    EXPECT_EQ(NO_ERROR, rc, "hwrng test");
    if (rc == NO_ERROR) {
        hwrng_show_data(_rng_buf, 32);
    }
}

TEST(hwrng, var_rng_req_test) {
    int rc;
    unsigned int i;
    size_t req_cnt;
    /* Issue 100 hwrng requests of variable sizes */
    for (i = 0; i < 100; i++) {
        req_cnt = ((size_t)rand() % sizeof(_rng_buf)) + 1;
        rc = trusty_rng_hw_rand(_rng_buf, req_cnt);
        EXPECT_EQ(NO_ERROR, rc, "hwrng test");
        if (rc != NO_ERROR) {
            TLOGI("trusty_rng_hw_rand returned %d\n", rc);
            continue;
        }
    }
}

TEST(hwrng, stats_test) {
    int rc;
    unsigned int i;
    size_t req_cnt;
    uint32_t exp_cnt;
    uint32_t cnt = 0;
    uint32_t ave = 0;
    uint32_t dev = 0;
    /* issue 100x256 bytes requests */
    req_cnt = 256;
    exp_cnt = 1000 * req_cnt;
    memset(_hist, 0, sizeof(_hist));
    for (i = 0; i < 1000; i++) {
        rc = trusty_rng_hw_rand(_rng_buf, req_cnt);
        EXPECT_EQ(NO_ERROR, rc, "hwrng test");
        if (rc != NO_ERROR) {
            TLOGI("trusty_rng_hw_rand returned %d\n", rc);
            continue;
        }
        hwrng_update_hist(_rng_buf, req_cnt);
    }

    /* check hwrng stats */
    for (i = 0; i < 256; i++)
        cnt += _hist[i];
    ave = cnt / 256;
    EXPECT_EQ(exp_cnt, cnt, "hwrng ttl sample cnt");
    EXPECT_EQ(1000, ave, "hwrng eve sample cnt");

    /*
     * Ideally data should be uniformly distributed
     * Calculate average deviation from ideal model
     */
    for (i = 0; i < 256; i++) {
        uint32_t val = (_hist[i] > ave) ? _hist[i] - ave : ave - _hist[i];
        dev += val;
    }
    dev /= 256;
    /*
     * Check if average deviation is within 5% of ideal model
     * which is fairly arbitrary requirement. It could be useful
     * to alert is something terribly wrong with rng source.
     */
    EXPECT_GT(50, dev, "average dev");
}

PORT_TEST(hwcrypto, "com.android.trusty.hwcrypto.test")
