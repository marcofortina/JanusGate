#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu

external_directory=$2

cp "$external_directory/board/x86_64/grub.cfg" \
    "$BINARIES_DIR/efi-part/EFI/BOOT/grub.cfg"
"$external_directory/board/common/create-data-image.sh"
support/scripts/genimage.sh \
    -c "$external_directory/board/x86_64/genimage.cfg"
