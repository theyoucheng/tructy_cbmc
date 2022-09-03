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

/*
 * Trusty fast internal system randomness source
 *
 * ***DO NOT USE THIS***
 *
 * This API should only be used for the CRYPTO_sysrand implementation used by
 * BoringSSL as a fast system source of randomness on each call to RAND_bytes.
 * Users should instead use the BoringSSL RNG directly via RAND_bytes() and
 * similar APIs.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * trusty_rng_internal_system_rand() - DO NOT USE: You should use RAND_bytes()
 *                                     in BoringSSL.
 */
int trusty_rng_internal_system_rand(uint8_t* data, size_t len);
