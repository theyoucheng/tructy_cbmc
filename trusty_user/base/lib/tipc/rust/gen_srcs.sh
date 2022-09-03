#!/usr/bin/env bash
set -euo pipefail

bindgen trusty/user/base/include/user/trusty_ipc.h \
      -o trusty/user/base/lib/tipc/rust/src/ipc_sys.rs \
      --use-core \
      --ctypes-prefix 'trusty_sys' \
      --allowlist-var 'IPC_.*' \
      --allowlist-var 'INFINITE_TIME' \
      --allowlist-type 'handle_t' \
      -- \
      "--sysroot=fake_sysroot" \
      "-isystem" \
      "external/trusty/musl/arch/aarch64" \
      "-isystem" \
      "external/trusty/musl/arch/generic" \
      "-isystem" \
      "external/trusty/musl/include" \
      "-Iexternal/lk/include/uapi" \
      "-Itrusty/kernel/include/uapi" \
      "-Iexternal/lk/include/shared" \
