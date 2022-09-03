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

#pragma once

#include <lk/compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <trusty_ipc.h>

__BEGIN_CDECLS

/**
 * struct shm - structure tracking shared memory
 * @memref: handle to shared memory region
 * @base:   base address of shared memory region if mapped, NULL otherwise
 * @len:    length of shared memory region if mapped, 0 otherwise
 */
struct shm {
    handle_t memref;
    void* base;
    size_t len;
};

static bool inline shm_is_mapped(struct shm* shm) {
    return shm->base;
}

static void inline shm_init(struct shm* shm,
                            handle_t memref,
                            void* base,
                            size_t len) {
    shm->memref = memref;
    shm->base = base;
    shm->len = len;
}

/**
 * shm_alloc() - allocate shared memory
 * @shm: pointer to &struct shm to be initialized
 * @len: amount of memory requested
 *
 * Return: 0 on success, negative error code on error
 */
int shm_alloc(struct shm* shm, size_t len);

/**
 * shm_free() - free shared memory
 * @shm: pointer to &struct shm previously initialized with shm_alloc()
 */
void shm_free(struct shm* shm);

/**
 * shm_mmap() - map shared memory region
 * @shm:    pointer to &struct shm to be initialized
 * @memref: handle to memory to be mapped
 * @len:    length of memory region referenced by @memref
 *
 * Return: 0 on success, negative error code on error
 */
int shm_mmap(struct shm* shm, handle_t memref, size_t len);

/**
 * shm_munmap() - unmap shared memory
 * @shm: pointer to &struct shm previously initialized with shm_mmap()
 */
void shm_munmap(struct shm* shm);

/**
 * shm_munmap() - zero out contents of shared memory
 * @shm: pointer to &struct shm
 */
void shm_clear(struct shm* shm);

__END_CDECLS
