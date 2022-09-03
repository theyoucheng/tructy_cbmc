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

#pragma once

#include <stdint.h>

#define SMC_SERVICE_PORT "com.android.trusty.kernel.smc"

#define SMC_MSG_NUM_PARAMS 4

/**
 * struct smc_msg - request/response structure for SMC
 * @params: parameters of smc call
 */
struct smc_msg {
    uint64_t params[SMC_MSG_NUM_PARAMS];
};
