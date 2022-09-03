/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <lib/tipc/tipc_srv.h>

/**
 * struct srv_state - global state of the metrics server
 * @hset:        handle set managed by this server
 * @client_chan: handle to client channel
 */
struct srv_state {
    struct tipc_hset* hset;
    handle_t client_chan;
};

static inline void set_srv_state(struct tipc_port* port,
                                 struct srv_state* state) {
    port->priv = state;
}

static inline struct srv_state* get_srv_state(const struct tipc_port* port) {
    return (struct srv_state*)(port->priv);
}

/**
 * add_metrics_service() - initialize metrics service
 * @state: pointer to &struct srv_state
 *
 * Return: 0 on success, negative error code on error
 */
int add_metrics_service(struct srv_state* state);

/**
 * add_metrics_consumer_service() - initialize metrics consumer service
 * @state: pointer to &struct srv_state
 *
 * Return: 0 on success, negative error code on error
 */
int add_metrics_consumer_service(struct srv_state* state);
