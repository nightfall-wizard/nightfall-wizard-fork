# Nightfall Node Kit self-verification

Status: prototype, non-consensus-active.

This document describes the first reviewable slice of a Nightfall Node Kit:
a read-only local self-verification tool for users who want to understand
whether their local node/wallet environment is independently verifiable and
operationally safe.

## Goals

- report whether the configured datadir exists and is readable
- reject source-code checkouts passed accidentally as datadirs
- skip backup-signal checks when datadir validation has already failed
- warn when a readable datadir has no recognizable node-state filename signals
- report whether the selected network is recognized
- report whether the checkpoint shortcut is active or disabled through
  `NIGHTFALL_NO_ASSUME_VALID=1`
- report whether the supplied RPC bind appears loopback-only
- detect wallet/backup filename signals without reading secret contents
- produce both human-readable and JSON output for UI integration
- support `--fail-on-warn` for automation that must fail on warnings

## Non-goals

- no consensus change
- no block validation
- no wallet mutation
- no seed, view-key, or vault-content parsing
- no claim that the setup is safe merely because the tool returns OK

## Privacy boundary

The tool must not print seed phrases, view keys, wallet contents, or RPC
credentials. The initial implementation inspects filenames only for backup
signals and never reads secret-bearing file contents.

## Review focus

Review should focus on the boundary between helpful user diagnostics and
unsafe disclosure. Warnings should be conservative, explicit, and actionable.
