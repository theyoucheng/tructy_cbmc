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

#define TLOG_TAG "apploader-app-version"

#include <assert.h>
#include <inttypes.h>
#include <lib/app_manifest/app_manifest.h>
#include <lib/storage/storage.h>
#include <lib/system_state/system_state.h>
#include <stdarg.h>
#include <trusty_log.h>
#include <uapi/err.h>
#include <algorithm>
#include <array>

#include "apploader_package.h"

constexpr const char kStorageFilePrefix[] = "app_version.";

/*
 * Size of storage file name:
 * length of the prefix + UUID (32 bytes) + null terminator
 */
constexpr size_t kStorageFileNameSize =
        (countof(kStorageFilePrefix) - 1) + 32 + 1;
using StorageFileName = std::array<char, kStorageFileNameSize>;

static StorageFileName get_storage_file_name(const uuid_t* app_uuid) {
    StorageFileName result;

    __UNUSED int written = snprintf(
            result.data(), result.size(),
            "%s%08" PRIx32 "%04" PRIx16 "%04" PRIx16 "%02" PRIx8 "%02" PRIx8
            "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8
            "%02" PRIx8,
            kStorageFilePrefix, app_uuid->time_low, app_uuid->time_mid,
            app_uuid->time_hi_and_version, app_uuid->clock_seq_and_node[0],
            app_uuid->clock_seq_and_node[1], app_uuid->clock_seq_and_node[2],
            app_uuid->clock_seq_and_node[3], app_uuid->clock_seq_and_node[4],
            app_uuid->clock_seq_and_node[5], app_uuid->clock_seq_and_node[6],
            app_uuid->clock_seq_and_node[7]);

    assert(static_cast<size_t>(written) == result.size() - 1);

    return result;
}

/*
 * Retrieves the version of an application from storage.
 */
static int get_app_storage_version(const uuid_t* app_uuid,
                                   uint32_t* app_version) {
    assert(app_version);

    auto file_name = get_storage_file_name(app_uuid);

    int rc;
    storage_session_t session;
    rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("Error opening storage session (%d)\n", rc);
        goto err_open_session;
    }

    file_handle_t file;
    rc = storage_open_file(session, &file, file_name.data(), 0, 0);
    if (rc < 0) {
        if (rc == ERR_NOT_FOUND) {
            /* File does not exist, treat this case as version 0 */
            *app_version = 0;
            rc = 0;
        } else {
            TLOGE("Error opening storage file (%d)\n", rc);
        }
        goto err_open_file;
    }

    uint32_t file_version;
    rc = storage_read(file, 0, &file_version, sizeof(file_version));
    if (rc != sizeof(file_version)) {
        TLOGE("Error reading file (%d)\n", rc);
        goto err_read_file;
    }

    *app_version = file_version;
    rc = NO_ERROR;

err_read_file:
    storage_close_file(file);
err_open_file:
err_get_file:
    storage_close_session(session);
err_open_session:
    return rc;
}

static int update_app_version(uuid_t* app_uuid, uint32_t new_version) {
    int rc;
    auto file_name = get_storage_file_name(app_uuid);
    storage_session_t session;
    rc = storage_open_session(&session, STORAGE_CLIENT_TP_PORT);
    if (rc < 0) {
        TLOGE("Error opening storage session (%d)\n", rc);
        goto err_open_session;
    }

    file_handle_t file;
    rc = storage_open_file(session, &file, file_name.data(),
                           STORAGE_FILE_OPEN_CREATE, 0);
    if (rc < 0) {
        TLOGE("Error opening storage file (%d)\n", rc);
        goto err_open_file;
    }

    rc = storage_write(file, 0, &new_version, sizeof(new_version),
                       STORAGE_OP_COMPLETE);
    if (rc != sizeof(new_version)) {
        TLOGE("Error writing to file (%d)\n", rc);
    }

    rc = NO_ERROR;

err_write_file:
    storage_close_file(file);
err_open_file:
    storage_close_session(session);
err_open_session:
    return rc;
}

extern "C" bool apploader_check_app_version(
        struct apploader_package_metadata* pkg_meta) {
    int rc;
    struct app_manifest_iterator iter;
    rc = app_manifest_iterator_reset(
            &iter, reinterpret_cast<const char*>(pkg_meta->manifest_start),
            pkg_meta->manifest_size);
    if (rc != NO_ERROR) {
        TLOGE("Error parsing manifest (%d)\n", rc);
        return false;
    }

    /* Apps without a version in the manifest get a default of 0 */
    uuid_t app_uuid;
    uint32_t manifest_version = 0;

    struct app_manifest_config_entry entry;
    while (app_manifest_iterator_next(&iter, &entry, &rc)) {
        switch (entry.key) {
        case APP_MANIFEST_CONFIG_KEY_UUID:
            memcpy(&app_uuid, &entry.value.uuid, sizeof(uuid));
            break;
        case APP_MANIFEST_CONFIG_KEY_VERSION:
            manifest_version = entry.value.version;
            break;
        case APP_MANIFEST_CONFIG_KEY_APP_NAME:
        case APP_MANIFEST_CONFIG_KEY_MIN_STACK_SIZE:
        case APP_MANIFEST_CONFIG_KEY_MIN_HEAP_SIZE:
        case APP_MANIFEST_CONFIG_KEY_MAP_MEM:
        case APP_MANIFEST_CONFIG_KEY_MGMT_FLAGS:
        case APP_MANIFEST_CONFIG_KEY_START_PORT:
        case APP_MANIFEST_CONFIG_KEY_PINNED_CPU:
        case APP_MANIFEST_CONFIG_KEY_MIN_SHADOW_STACK_SIZE:
            /* We don't care about these here */
            break;
        }
    }
    if (rc != NO_ERROR) {
        TLOGE("Error iterating over manifest entries (%d)\n", rc);
        return false;
    }

    /* Check application version */
    uint32_t storage_version;
    rc = get_app_storage_version(&app_uuid, &storage_version);
    if (rc < 0) {
        TLOGE("Error retrieving application version from storage (%d)\n", rc);
        return false;
    }
    if (manifest_version < storage_version) {
        TLOGE("Application package version (%" PRIu32
              ") is lower than storage version (%" PRIu32 ")\n",
              manifest_version, storage_version);
        return false;
    }

    if (!system_state_app_loading_skip_version_update() &&
        manifest_version > storage_version) {
        rc = update_app_version(&app_uuid, manifest_version);
        if (rc < 0) {
            TLOGE("Error updating application version in storage (%d)\n", rc);
            return false;
        }
    }

    return true;
}
