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

//! Trusty simple logger backend
//!
//! Logs to stderr based on a compile-time configured log level.

#![no_std]

use log::{Level, LevelFilter, Log, Metadata, Record};
use trusty_std::io::{stderr, Write};
use trusty_std::write;

pub struct TrustyLogger;

impl Log for TrustyLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let _ = write!(stderr(), "{} - {}\n", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: TrustyLogger = TrustyLogger;

pub fn init() {
    log::set_logger(&LOGGER).expect("Could not set global logger");
    log::set_max_level(LevelFilter::Info);
}
