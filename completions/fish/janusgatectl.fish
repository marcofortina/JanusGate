# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

# Test whether no top-level JanusGate command has been entered.
function __janusgatectl_needs_command
    not __fish_seen_subcommand_from \
        status health stats network policy domain blocklist source events \
        audit user token certificate backup diagnostics logging config service \
        system ping
end

# Test whether one command family still needs its immediate subcommand.
function __janusgatectl_needs_subcommand
    set --local family $argv[1]
    set --erase argv[1]
    __fish_seen_subcommand_from $family
    and not __fish_seen_subcommand_from $argv
end

complete --command janusgatectl --no-files
complete --command janusgatectl --long-option socket \
    --description 'Local control socket' --require-parameter --force-files
complete --command janusgatectl --long-option endpoint \
    --description 'HTTPS management origin' --require-parameter
complete --command janusgatectl --long-option token-file \
    --description 'Private API token file' --require-parameter --force-files
complete --command janusgatectl --long-option passphrase-file \
    --description 'Private backup passphrase file' --require-parameter --force-files
complete --command janusgatectl --long-option client-cert \
    --description 'mTLS client certificate' --require-parameter --force-files
complete --command janusgatectl --long-option client-key \
    --description 'mTLS client private key' --require-parameter --force-files
complete --command janusgatectl --long-option ca-file \
    --description 'PEM trust anchors' --require-parameter --force-files
complete --command janusgatectl --long-option timeout \
    --description 'Remote request timeout' --require-parameter
complete --command janusgatectl --long-option json \
    --description 'Write compact JSON'
complete --command janusgatectl --long-option quiet \
    --description 'Suppress successful output'
complete --command janusgatectl --long-option verbose \
    --description 'Report request details'
complete --command janusgatectl --long-option yes \
    --description 'Confirm destructive operations'
complete --command janusgatectl --long-option include-private-key \
    --description 'Include the server key in a full backup'
complete --command janusgatectl --long-option help \
    --description 'Display command help'
complete --command janusgatectl --long-option version \
    --description 'Display version information'

complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments status --description 'Return appliance status'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments health --description 'Return service health'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments stats --description 'Return Prometheus metrics'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments network --description 'Manage inline networking'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments policy --description 'Manage policy records'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments domain --description 'Manage simple domain rules'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments blocklist --description 'Import or export blocklists'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments source --description 'Manage blocklist sources'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments events --description 'List operational events'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments audit --description 'List or verify audit records'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments user --description 'Manage local users'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments token --description 'Manage API tokens'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments certificate --description 'Manage the server identity'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments backup --description 'Create, inspect, or restore backups'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments diagnostics --description 'Create a diagnostic archive'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments logging --description 'Manage operational logging'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments config --description 'Validate or reload configuration'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments service --description 'Manage JanusGate services'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments system --description 'Manage appliance power'
complete --command janusgatectl --condition __janusgatectl_needs_command \
    --arguments ping --description 'Check the local control socket'

complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand network show validate apply set confirm rollback' \
    --arguments 'show validate apply set confirm rollback'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand policy list show add update remove simulate reload' \
    --arguments 'list show add update remove simulate reload'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand domain block allow remove' \
    --arguments 'block allow remove'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand blocklist list import export' \
    --arguments 'list import export'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand source list add update refresh enable disable' \
    --arguments 'list add update refresh enable disable'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand audit verify' --arguments verify
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand user list add update disable password totp' \
    --arguments 'list add update disable password totp'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand token list create revoke' \
    --arguments 'list create revoke'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand certificate show install csr' \
    --arguments 'show install csr'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand backup create inspect restore' \
    --arguments 'create inspect restore'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand diagnostics create' \
    --arguments create
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand logging show set traces' \
    --arguments 'show set traces'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand config validate reload' \
    --arguments 'validate reload'
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand service restart' \
    --arguments restart
complete --command janusgatectl \
    --condition '__janusgatectl_needs_subcommand system reboot shutdown' \
    --arguments 'reboot shutdown'

complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from backup; and __fish_seen_subcommand_from create' \
    --arguments 'configuration full'
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from policy; and __fish_seen_subcommand_from show add update remove' \
    --arguments 'domain destination'

complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from network; and __fish_seen_subcommand_from validate apply set' \
    --force-files
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from logging; and __fish_seen_subcommand_from set' \
    --force-files
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from policy; and __fish_seen_subcommand_from add update simulate' \
    --force-files
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from blocklist; and __fish_seen_subcommand_from import' \
    --force-files
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from source; and __fish_seen_subcommand_from add update' \
    --force-files
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from user; and __fish_seen_subcommand_from add update password' \
    --force-files
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from token; and __fish_seen_subcommand_from create' \
    --force-files
complete --command janusgatectl \
    --condition '__fish_seen_subcommand_from certificate; and __fish_seen_subcommand_from install csr' \
    --force-files
