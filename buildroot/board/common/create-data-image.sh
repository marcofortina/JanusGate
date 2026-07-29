#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

data_image=$BINARIES_DIR/data.ext4
data_uuid=6a616e75-7367-4174-8567-617465000002

truncate -s 256M "$data_image"
E2FSPROGS_FAKE_TIME=${SOURCE_DATE_EPOCH:-0} \
    "$HOST_DIR/sbin/mkfs.ext4" -q -F -L JANUSGATE_DATA \
    -U "$data_uuid" \
    -E "lazy_itable_init=0,lazy_journal_init=0,hash_seed=$data_uuid" \
    "$data_image"
