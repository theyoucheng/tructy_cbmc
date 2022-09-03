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

#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <trusty/string.h>
#include <trusty/time.h>
#include <trusty/uuid.h>
#include <trusty_unittest.h>
#include <unistd.h>

#define CHECK_ERRNO(e)       \
    do {                     \
        ASSERT_EQ(e, errno); \
        errno = 0;           \
    } while (0)
#define CLEAR_ERRNO() \
    do {              \
        errno = 0;    \
    } while (0)

typedef struct libc {
} libc_t;

TEST_F_SETUP(libc) {
    /* Isolate the tests. */
    CLEAR_ERRNO();
}

TEST_F_TEARDOWN(libc) {
    /* errno should have been checked and cleared if the test sets errno. */
    CHECK_ERRNO(0);

test_abort:;
}

/*
 * Smoke test to make sure the endian functions are defined.
 * Musl may or may not expose them, depending on the feature test macros.
 */
TEST_F(libc, endian) {
    const uint32_t test_data = 0x12345678;
    /* TODO test le32, etc, once they are provided. */
    ASSERT_EQ(test_data, be32toh(htobe32(test_data)));
test_abort:;
}

TEST_F(libc, memset_test) {
    unsigned char buf[130];
    buf[0] = 0;
    buf[129] = 0;
    for (int val = 1; val < 256; val <<= 1) {
        memset(&buf[1], val, 128);
        ASSERT_EQ(0, buf[0], "iteration %d", val);
        for (unsigned int i = 1; i < 128; i++) {
            ASSERT_EQ(val, buf[i], "iteration %d", val);
        }
        ASSERT_EQ(0, buf[129], "iteration %d", val);
    }

test_abort:;
}

TEST_F(libc, memcmp_test) {
    unsigned char buf1[128];
    unsigned char buf2[128];

    /* Identical buffers. */
    memset(buf1, 7, sizeof(buf1));
    memset(buf2, 7, sizeof(buf2));
    ASSERT_EQ(0, memcmp(buf1, buf2, sizeof(buf1)));

    /* buf1 slightly greater. */
    buf1[127] = 9;
    buf2[127] = 8;
    ASSERT_LT(0, memcmp(buf1, buf2, sizeof(buf1)));

    /* buf1 much greater. */
    buf1[127] = 127;
    buf2[127] = 0;
    ASSERT_LT(0, memcmp(buf1, buf2, sizeof(buf1)));

    /* buf2 slightly greater. */
    buf1[127] = 8;
    buf2[127] = 9;
    ASSERT_GT(0, memcmp(buf1, buf2, sizeof(buf1)));

    /* buf2 much greater. */
    buf1[127] = 0;
    buf2[127] = 127;
    ASSERT_GT(0, memcmp(buf1, buf2, sizeof(buf1)));

    /* Buffers are identical again. */
    memcpy(buf2, buf1, sizeof(buf1));
    ASSERT_EQ(0, memcmp(buf1, buf2, sizeof(buf1)));

test_abort:;
}

TEST_F(libc, strcmp_test) {
    ASSERT_EQ(0, strcmp("", ""));
    ASSERT_GT(0, strcmp("", "bar"));
    ASSERT_LT(0, strcmp("bar", ""));

    ASSERT_EQ(0, strcmp("bar", "bar"));
    ASSERT_GT(0, strcmp("bar", "baz"));
    ASSERT_LT(0, strcmp("baz", "bar"));

    ASSERT_GT(0, strcmp("bar", "barbar"));
    ASSERT_LT(0, strcmp("barbar", "bar"));

    char negative[2] = {-127, 0};
    char positive[2] = {0, 0};
    // strcmp must treat characters as unsigned
    ASSERT_LT(0, strcmp(negative, positive));
    ASSERT_LT(0, strncmp(negative, positive, 1));

test_abort:;
}

#define MSEC 1000000ULL

/*
 * Smoke test the time-related functions.
 * As long as gettime and nanosleep behave semi-reasonablly, we're happy.
 */
TEST_F(libc, time) {
    int64_t begin = 0;
    int64_t end = 0;
    int64_t delta = 0;

    trusty_gettime(0, &begin);
    trusty_nanosleep(0, 0, 10 * MSEC);
    trusty_gettime(0, &end);
    delta = end - begin;

    ASSERT_LT(1 * MSEC, delta);
    /* We've observed 200 ms sleeps in the emulator, so be generous. */
    ASSERT_LT(delta, 1000 * MSEC);

test_abort:;
}

/* Smoke test because we mocked out timezone functions. */
TEST_F(libc, localtime) {
    time_t time = 0;
    struct tm* result = localtime(&time);
    ASSERT_NE(NULL, result);

    /* Epoch. */
    EXPECT_EQ(70, result->tm_year);
    EXPECT_EQ(0, result->tm_mon);
    EXPECT_EQ(1, result->tm_mday);
    EXPECT_EQ(0, result->tm_hour);
    EXPECT_EQ(0, result->tm_min);
    EXPECT_EQ(0, result->tm_sec);

    time += 24 * 60 * 60;
    result = localtime(&time);
    ASSERT_NE(NULL, result);

    EXPECT_EQ(70, result->tm_year);
    EXPECT_EQ(0, result->tm_mon);
    EXPECT_EQ(2, result->tm_mday);
    EXPECT_EQ(0, result->tm_hour);
    EXPECT_EQ(0, result->tm_min);
    EXPECT_EQ(0, result->tm_sec);

test_abort:;
}

TEST_F(libc, snprintf_test) {
    char buffer[16];
    ASSERT_EQ(17, snprintf(buffer, sizeof(buffer), "%d %x %s...", 12345, 254,
                           "hello"));
    ASSERT_EQ(0, strcmp(buffer, "12345 fe hello."));

test_abort:;
}

TEST_F(libc, atoi_test) {
    ASSERT_EQ(12345, atoi("12345"));
    ASSERT_EQ(-67890, atoi("-67890"));
    /* Note: Out-of-bound values are undefined behavior. */

test_abort:;
}

TEST_F(libc, print_test) {
    /*
     * Test printing compiles and doesn't crash. Yes, this is a weak test.
     * A stronger test would be better, but also more complicated. Stay simple,
     * for now.
     */
    printf("Hello, stdout.\n");
    fprintf(stderr, "Hello, stderr.\n");
    CHECK_ERRNO(0);

test_abort:;
}

TEST_F(libc, print_float_test) {
    /*
     * %f should be valid and not cause an error, even if floating point
     * support is disabled.
     */
    printf("num: %f\n", 1.23);
    CHECK_ERRNO(0);

test_abort:;
}

TEST_F(libc, print_errno_test) {
    /*
     * %m is not supported, but should not be an error, either.
     */
    printf("err: %m\n");
    CHECK_ERRNO(0);

test_abort:;
}

TEST_F(libc, print_bad_test) {
    printf("[%k]\n");
    /* TODO: EINVAL */
    CLEAR_ERRNO();

test_abort:;
}

TEST_F(libc, malloc_loop) {
    for (int i = 0; i < 1024; i++) {
        void* ptr = malloc(4096 * 3);
        ASSERT_NE(0, ptr, "iteration %d", i);
        free(ptr);
    }

test_abort:;
}

TEST_F(libc, malloc_oom) {
    void* ptr = malloc(8192 * 1024);
    ASSERT_EQ(0, ptr);
    /* TODO: ENOMEM */
    CLEAR_ERRNO();

test_abort:;
}

static uintptr_t expected_malloc_alignment(size) {
    /* TODO use ffs? */
    if (size >= 16) {
        return sizeof(void*) * 2;
    } else if (size >= 8) {
        return 8;
    } else if (size >= 4) {
        return 4;
    } else if (size >= 2) {
        return 2;
    } else {
        return 1;
    }
}

TEST_F(libc, malloc_alignment) {
    for (int size = 2; size < 256; size++) {
        const uintptr_t alignment_mask = expected_malloc_alignment(size) - 1;
        void* ptr1 = malloc(size);
        void* ptr2 = malloc(size / 2); /* Try to shake up the alignment. */
        void* ptr3 = malloc(size);

        ASSERT_EQ(0, (uintptr_t)ptr1 & alignment_mask, "size %d / align %zu",
                  size, alignment_mask + 1);
        ASSERT_EQ(0, (uintptr_t)ptr3 & alignment_mask, "size %d / align %zu",
                  size, alignment_mask + 1);

        free(ptr3);
        free(ptr2);
        free(ptr1);
    }
test_abort:;
}

/*
 * Grab the frame pointer in a simple, non-inlined function.
 * Note this isn't a static function. We're trying to game the optimizer and
 * ensure it doesn't change the calling convention.
 */
__attribute__((__noinline__)) uintptr_t frame_ptr(void) {
    return (uintptr_t)__builtin_frame_address(0);
}

TEST_F(libc, stack_alignment) {
    /*
     * On all the platforms we support, the frame pointer should be aligned to 2
     * times pointer size. This includes x86_64 because the stack pointer is
     * implicitly re-aligned after function entry before it becomes the frame
     * pointer.
     * Note that this test passing does not guarantee correctness, but it can
     * catch badness.
     */
    const uintptr_t alignment_mask = sizeof(void*) * 2 - 1;
    ASSERT_EQ(0, frame_ptr() & alignment_mask);

test_abort:;
}

TEST_F(libc, stack_cookies) {
    uint64_t* p = (uint64_t*)getauxval(AT_RANDOM);
    ASSERT_NE(0, p);
    ASSERT_EQ(true, 0 != *p || 0 != *(p + 1));

test_abort:;
}

#if __has_feature(shadow_call_stack)
void** guard_region_ptr(void);

TEST_F(libc, shadow_call_stack) {
    /*
     * Leaf functions keep return address in the link register but the call
     * to guard_region_ptr will not get inlined which makes this a non-leaf
     * function -> return address of this function goes on the shadow stack
     */
    void** guard_region_top = guard_region_ptr();
    ASSERT_NE(0, guard_region_top);

    /* Get return address from stack */
    void* ret_addr = __builtin_return_address(0);
    /*
     * Guard region top points to next free word so the
     * shadow copy of the return address is right below
     */
    void* shadow_ret_addr = *(guard_region_top - 1);
    ASSERT_EQ(ret_addr, shadow_ret_addr);

test_abort:;
}
#endif /* __has_feature(shadow_call_stack) */

#define SCNPRINTF_TEST_BUF_LEN 8
TEST_F(libc, scnprintf) {
    char buf[SCNPRINTF_TEST_BUF_LEN];
    const size_t buf_size = SCNPRINTF_TEST_BUF_LEN - 2;

    buf[0] = 'z';
    /* We should always return 0 in the case of a zero size */
    EXPECT_EQ(0, scnprintf(buf, 0, "foo"));
    /* We should have written nothing to the buffer */
    EXPECT_EQ('z', buf[0]);

    buf[buf_size] = 'q';
    /* If we would overflow, we should return chars printed */
    EXPECT_EQ(buf_size - 1, scnprintf(buf, buf_size, "aaaaaaa"));
    /* If we would overflow, we should also not have written past end */
    EXPECT_EQ('q', buf[buf_size]);
    /* The buffer should still be null terminated */
    EXPECT_EQ(0, buf[buf_size - 1]);

    /* If we would fit, we should return the same as snprintf */
    EXPECT_EQ(3, scnprintf(buf, buf_size, "%d\n", 10));
    /* If it would fit, there should be a null terminator */
    EXPECT_EQ(buf[3], 0);

test_abort:;
}

TEST_F(libc, str_to_uuid) {
    const char* valid_str = "b100aae1-c0b3-4b8b-9e25-e69523968f7e";
    const char* invalid_str;
    struct uuid res_uuid;
    struct uuid expected_uuid = {
            0xb100aae1,
            0xc0b3,
            0x4b8b,
            {0x9e, 0x25, 0xe6, 0x95, 0x23, 0x96, 0x8f, 0x7e}};

    invalid_str = "b100aae1-c0b3-4b8b-9e25-e69523968f7";
    /* The string must be exactly 36 characters */
    EXPECT_EQ(-1, str_to_uuid(invalid_str, &res_uuid));

    invalid_str = "b100aae1c0b3-4b8b-9e25-e69523968f7e";
    /* There must be exactly 5 groups */
    EXPECT_EQ(-1, str_to_uuid(invalid_str, &res_uuid));

    invalid_str = "b100aa-e1c0b3-4b8b-9e25-e69523968f7e";
    /* Hyphens must be at specific locations */
    EXPECT_EQ(-1, str_to_uuid(invalid_str, &res_uuid));

    invalid_str = "g100aae1-c0b3-4b8b-9e25-e69523968f7e";
    /* The string must contain only hyphens and hex characters  */
    EXPECT_EQ(-1, str_to_uuid(invalid_str, &res_uuid));

    invalid_str = "B100aae1-c0b3-4b8b-9e25-e69523968f7e";
    /* Hex characters must be lower case  */
    EXPECT_EQ(-1, str_to_uuid(invalid_str, &res_uuid));

    EXPECT_EQ(0, str_to_uuid(valid_str, &res_uuid));

    EXPECT_EQ(0, memcmp(&expected_uuid, &res_uuid, sizeof(struct uuid)));
}

TEST_F(libc, uuid_to_str) {
    const char* expected_str = "b100aae1-c0b3-4b8b-9e25-e69523968f7e";
    const char* zero_str = "00000000-0000-0000-0000-000000000000";
    struct uuid zero_uuid = {0};
    char result_str[UUID_STR_SIZE];
    struct uuid uuid = {0xb100aae1,
                        0xc0b3,
                        0x4b8b,
                        {0x9e, 0x25, 0xe6, 0x95, 0x23, 0x96, 0x8f, 0x7e}};

    /* Check for correct padding */
    uuid_to_str(&zero_uuid, result_str);
    EXPECT_EQ(0, strncmp(zero_str, result_str, UUID_STR_SIZE));

    uuid_to_str(&uuid, result_str);
    EXPECT_EQ(0, strncmp(expected_str, result_str, UUID_STR_SIZE));
}

/*
 * We're linking a prebuilt libgcc / compiler_rt provided by the toolchain.
 * It wasn't designed for Trusty, so does it actually work? If we set things up
 * wrong there may be ABI issues. One way to smoke these issues out is call
 * functions that take floating point arguments. However - libgcc does not
 * provide a full set of functions for every arch, only the ones it expects to
 * use. This means we need to do some arch-specific testing.
 */

#ifdef __arm__
extern double __extendsfdf2(float a);
extern float __truncdfsf2(double a);

TEST_F(libc, float_builtins) {
    EXPECT_EQ(123, (int)__truncdfsf2(__extendsfdf2(123.0f)));
}
#endif

#ifdef __aarch64__
extern long double __extendsftf2(float a);
extern float __trunctfsf2(long double a);

TEST_F(libc, float_builtins) {
    EXPECT_EQ(123, (int)__trunctfsf2(__extendsftf2(123.0f)));
}
#endif

/*
 * We provide a mock implementation of stdin because libcxx refers to it.
 * Make sure the mock behaves in a reasonable manner.
 */
TEST_F(libc, getc) {
    EXPECT_EQ(EOF, getc(stdin));

test_abort:;
}

#if __ARM_NEON__ || __ARM_NEON

#include <arm_neon.h>

/*
 * NOTE this is a fairly weak test that checks if a neon instruction can be
 * executed. This will help detect cases where the build flags do not match the
 * actual system the code is running on.
 */
TEST_F(libc, basic_neon) {
    int8x16_t block1 = vdupq_n_u8(0x55);
    int8x16_t block2 = vdupq_n_u8(0x33);
    int8x16_t expected;
    int8x16_t result;

    /* memset just to be sure. */
    memset(&expected, 0x66, sizeof(int8x16_t));

    result = veorq_s8(block1, block2);
    ASSERT_EQ(0, memcmp(&expected, &result, sizeof(int8x16_t)));

test_abort:;
}

#endif

TEST_F(libc, sbrk) {
    /* Allocating and releasing a small range should succeed */
    const ssize_t brk_test_size = 64;
    void* orig_brk = sbrk(brk_test_size);
    ASSERT_NE(orig_brk, (void*)-1);
    void* test_brk = sbrk(0);
    ASSERT_EQ(sbrk(-brk_test_size), test_brk);
    ASSERT_EQ(orig_brk, sbrk(0));

    /* Allocating an oversized range should fail */
    ASSERT_EQ(sbrk(10 * 4096), (void*)-1);
    ASSERT_EQ(errno, ENOMEM);

test_abort:
    CLEAR_ERRNO();
}

PORT_TEST(libc, "com.android.libctest");
