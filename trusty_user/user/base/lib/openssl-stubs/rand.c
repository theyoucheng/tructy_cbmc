/* * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <uapi/err.h>

#include <lib/rng/trusty_rng.h>
#include <lib/rng/trusty_rng_internal.h>
#include <openssl/rand.h>

#if defined(OPENSSL_IS_BORINGSSL)

/*
 * CRYPTO_sysrand is called by BoringSSL to obtain entropy from the OS on every
 * query for randomness. This needs to be fast, so we provide our own AES-CTR
 * PRNG seeded from hardware randomness, if available.
 */
__WEAK void CRYPTO_sysrand(uint8_t* out, size_t requested) {
    if (trusty_rng_internal_system_rand(out, requested) != NO_ERROR) {
        abort();
    }
}

/*
 * We want to seed the BoringSSL RNG from the hardware RNG directly, if
 * available.
 */
__WEAK void CRYPTO_sysrand_for_seed(uint8_t* out, size_t requested) {
    if (trusty_rng_hw_rand(out, requested) != NO_ERROR) {
        abort();
    }
}

#else

int RAND_poll(void) {
    return 0;
}

#endif /* OPENSSL_IS_BORINGSSL */
