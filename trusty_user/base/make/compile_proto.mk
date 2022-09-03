# Copyright (C) 2018 The Android Open Source Project
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

# This make file is used to compile protobuf files to .pb.c and .pb.h files
# using nanopb. To use this make file, add the following rule after including
# this file: $(eval $(call compile_proto,[input proto file],[output folder]))
# The generated .pb.c file is $(NANOPB_GENERATED_C), the generated .pb.h file
# is $(NANOPB_GENERATED_HEADER). The nanopb dependencies is at $(NANOPB_DEPS).
# Include them in your rule and then you could use the generated file in your
# code.

PREBUILTS_PROTOC_DIR := prebuilts/libprotobuf
PROTOC_PREBUILT := $(PWD)/$(PREBUILTS_PROTOC_DIR)/bin/protoc
NANOPB_DIR := external/nanopb-c
NANOPB_DEPS := $(NANOPB_DIR)/pb_common.c \
  $(NANOPB_DIR)/pb_encode.c \
  $(NANOPB_DIR)/pb_decode.c \

define compile_proto
INPUT_BASENAME := $$(basename $$(notdir $(1)))
NANOPB_GENERATED_C := $(2)/$$(INPUT_BASENAME).pb.c
NANOPB_GENERATED_HEADER := $(2)/$$(INPUT_BASENAME).pb.h
$$(NANOPB_GENERATED_C): INPUT_DIR=$$(dir $(1))
$$(NANOPB_GENERATED_C): $(1) \
    $(2)/nanopb-c/generator/proto/nanopb_pb2.py \
    $(2)/nanopb-c/generator/proto/plugin_pb2.py \
    | $(PROTOC_PREBUILT)
	$(hide) mkdir -p $(2)
	$(PROTOC_PREBUILT) \
  --plugin=protoc-gen-nanopb=$(2)/nanopb-c/generator/protoc-gen-nanopb \
  -I$(PREBUILTS_PROTOC_DIR)/include \
  -I$(2)/nanopb-c/generator/proto \
  -I$$(INPUT_DIR) \
  --nanopb_out=$(2) $$<

$$(NANOPB_GENERATED_HEADER): $$(NANOPB_GENERATED_C)

$(2)/nanopb-c: $(NANOPB_DIR)
	$(hide) mkdir -p $$@
	# Copy nanopb directory to work directory.
	$(hide) cp -r $(NANOPB_DIR)/* $$@
	# Copy the protobuf python library from prebuilt to work directory.
	$(hide) cp -r $(PREBUILTS_PROTOC_DIR)/python/google $$@/generator

$(2)/nanopb-c/generator/proto/nanopb_pb2.py: $(2)/nanopb-c
	# Need to generate the python file under the same folder as proto file
	# otherwise protoc would create a directory structure.
	$(hide) cd $(2)/nanopb-c/generator/proto/;$(PROTOC_PREBUILT) --python_out=. nanopb.proto

$(2)/nanopb-c/generator/proto/plugin_pb2.py: $(2)/nanopb-c
	$(hide) cd $(2)/nanopb-c/generator/proto/;$(PROTOC_PREBUILT) --python_out=. plugin.proto

endef
