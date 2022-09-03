#!/bin/bash
#
# Copyright (C) 2021 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This scripts generates an ECDSA private/public key pair
# for apploader signatures.

set -e

if [ "$#" -ne 2 ]; then
    echo -e "Usage: $0 <private key file> <public key file>"
    exit 1
fi

PRIVATE_KEY_FILE=$1
PUBLIC_KEY_FILE=$2

openssl ecparam \
    -genkey \
    -name prime256v1 \
    -noout \
    -outform DER \
    -out "$PRIVATE_KEY_FILE"

openssl ec \
    -inform DER \
    -in "$PRIVATE_KEY_FILE" \
    -pubout \
    -outform DER \
    -out "$PUBLIC_KEY_FILE"
