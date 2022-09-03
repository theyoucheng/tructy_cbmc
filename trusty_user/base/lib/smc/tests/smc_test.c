/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define TLOG_TAG "smc-test"

#include <lib/smc/smc_ipc.h>
#include <trusty_ipc.h>
#include <trusty_unittest.h>
#include <uapi/err.h>

typedef struct smc {
    handle_t channel;
} smc_t;

static const int msg_len = sizeof(struct smc_msg);

TEST_F_SETUP(smc) {
    int rc;

    rc = connect(SMC_SERVICE_PORT, IPC_CONNECT_WAIT_FOR_PORT);
    _state->channel = (handle_t)rc;
    ASSERT_GT(_state->channel, 0);

test_abort:;
}

TEST_F_TEARDOWN(smc) {
    close(_state->channel);
}

/* Macro to enable test cases for platform(s) on ARM and ARM64 architectures */
#if defined(ARCH_ARM) || defined(ARCH_ARM64)
#define ARM_ONLY_TEST(name) name
#else
#define ARM_ONLY_TEST(name) DISABLED_##name
#endif

/* Macro to enable test cases for generic ARM64 platform only */
#if defined(PLATFORM_GENERIC_ARM64)
#define GENERIC_ARM64_PLATFORM_ONLY_TEST(name) name
#else
#define GENERIC_ARM64_PLATFORM_ONLY_TEST(name) DISABLED_##name
#endif

/* ARM DEN 0028A(0.9.0) mandates that bits 23:16 must be zero for fast calls
 * (when bit 31 == 1) */
#define ILLEGAL_SMC ((long)0x80FF0000)
/* Return value for unknown SMC (defined by ARM DEN 0028A(0.9.0) */
#define SM_ERR_UNDEFINED_SMC ((int32_t)(-1))

/* Check that SM_ERR_UNDEFINED_SMC is returned for an unknown SMC number */
TEST_F(smc, ARM_ONLY_TEST(unknown_smc)) {
    int rc;
    struct smc_msg request = {
            .params[0] = ILLEGAL_SMC,
    };
    struct smc_msg response;

    rc = smc_send_request(_state->channel, &request);
    ASSERT_EQ(rc, msg_len);

    rc = smc_read_response(_state->channel, &response);
    ASSERT_EQ(rc, msg_len);
    ASSERT_EQ((int32_t)response.params[0], SM_ERR_UNDEFINED_SMC);

test_abort:;
}

/* Check that SMC service supports clients on multiple channels */
TEST_F(smc, ARM_ONLY_TEST(multiple_channels)) {
    int rc;
    handle_t channel1;
    handle_t channel2;
    struct smc_msg request = {
            .params[0] = ILLEGAL_SMC,
    };
    struct smc_msg response;

    channel1 = _state->channel;

    rc = connect(SMC_SERVICE_PORT, IPC_CONNECT_WAIT_FOR_PORT);
    channel2 = (handle_t)rc;
    ASSERT_GT(channel2, 0);

    rc = smc_send_request(channel1, &request);
    ASSERT_EQ(rc, msg_len);

    rc = smc_send_request(channel2, &request);
    ASSERT_EQ(rc, msg_len);

    rc = smc_read_response(channel1, &response);
    ASSERT_EQ(rc, msg_len);
    ASSERT_EQ((int32_t)response.params[0], SM_ERR_UNDEFINED_SMC);

    rc = smc_read_response(channel2, &response);
    ASSERT_EQ(rc, msg_len);
    ASSERT_EQ((int32_t)response.params[0], SM_ERR_UNDEFINED_SMC);

test_abort:
    close(channel2);
}

/* Following test cases rely on Trusty SPD to be enabled in EL3, and are thus
 * platform-specific. */

/* SMC numbers defined by ATF */
#define SMC_NR(entity, fn, fastcall, smc64)                               \
    (((((uint32_t)(fastcall)) & 0x1U) << 31U) | (((smc64)&0x1U) << 30U) | \
     (((entity)&0x3FU) << 24U) | ((fn)&0xFFFFU))

#define SMC_FASTCALL_NR(entity, fn) SMC_NR((entity), (fn), 1U, 0U)

#define SMC_ENTITY_PLATFORM_MONITOR 61

/*
 * Write character in r1 to debug console
 */
#define SMC_FC_DEBUG_PUTC SMC_FASTCALL_NR(SMC_ENTITY_PLATFORM_MONITOR, 0x0)

TEST_F(smc, GENERIC_ARM64_PLATFORM_ONLY_TEST(putc)) {
    int rc;
    struct smc_msg request = {
            .params[0] = SMC_FC_DEBUG_PUTC,
            .params[1] = 'd', /* prints 'd' to serial */
    };
    struct smc_msg response;

    rc = smc_send_request(_state->channel, &request);
    ASSERT_EQ(rc, msg_len);

    rc = smc_read_response(_state->channel, &response);
    ASSERT_EQ(rc, msg_len);
    ASSERT_EQ(response.params[0], 0);

test_abort:;
}

/*
 * Get register base address
 * r1: SMC_GET_GIC_BASE_GICD or SMC_GET_GIC_BASE_GICC
 */
#define SMC_GET_GIC_BASE_GICD 0
#define SMC_GET_GIC_BASE_GICC 1
#define SMC_FC_GET_REG_BASE SMC_FASTCALL_NR(SMC_ENTITY_PLATFORM_MONITOR, 0x1)

#define GICD_BASE 0x8000000
#define GICC_BASE 0x8010000

/* Check that we can query GICD base value from ATF */
TEST_F(smc, GENERIC_ARM64_PLATFORM_ONLY_TEST(get_gicd_base)) {
    int rc;
    struct smc_msg request = {
            .params[0] = SMC_FC_GET_REG_BASE,
            .params[1] = SMC_GET_GIC_BASE_GICD,
    };
    struct smc_msg response;

    rc = smc_send_request(_state->channel, &request);
    ASSERT_EQ(rc, msg_len);

    rc = smc_read_response(_state->channel, &response);
    ASSERT_EQ(rc, msg_len);
    ASSERT_EQ(response.params[0], GICD_BASE);

test_abort:;
}

TEST_F(smc, GENERIC_ARM64_PLATFORM_ONLY_TEST(get_gicc_base)) {
    int rc;
    struct smc_msg request = {
            .params[0] = SMC_FC_GET_REG_BASE,
            .params[1] = SMC_GET_GIC_BASE_GICC,
    };
    struct smc_msg response;

    rc = smc_send_request(_state->channel, &request);
    ASSERT_EQ(rc, msg_len);

    rc = smc_read_response(_state->channel, &response);
    ASSERT_EQ(rc, msg_len);
    ASSERT_EQ(response.params[0], GICC_BASE);

test_abort:;
}

PORT_TEST(smc, "com.android.trusty.smc.test");
