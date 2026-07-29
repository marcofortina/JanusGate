#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

external_directory=$2

"$external_directory/board/common/create-data-image.sh"
support/scripts/genimage.sh \
    -c "$external_directory/board/aarch64/genimage.cfg"
