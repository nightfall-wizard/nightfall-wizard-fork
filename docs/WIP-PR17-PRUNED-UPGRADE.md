# Existing 1.1.x pruned datadirs: safe upgrade boundary

This is an **unfinished migration design**, not a validated automatic migration.

Version 1.1.2 pruned datadirs may not carry the semantic integrity seals
introduced by PR #17. Their old block bodies are no longer available.
Hashing the remaining local files **cannot reconstruct independent proof**
that those files describe a valid historical chain.

## Safe current behavior

- Fail closed without rewriting chain metadata or any persisted state.
- Never automatically calculate and bless new local seals from unverified
  legacy pruned contents. This would turn local corruption into trusted state.
- Back up the datadir and wallet before doing anything.
- Retain the wallet, explicitly resync chain history from independently
  verified archive bodies, then write new local seals only after validation.
- On failure/interruption, refuse startup and retain the original backup.

The regression in this WIP branch asserts byte-for-byte preservation
of old metadata, horizon, headers, and retained bodies on refused startup.

## Still required before merging

A real untouched 1.1.2 pruned fixture and tested recovery UX, an explicit
safe upgrade path, interruption fault injection, mainnet-scale startup
benchmark, and maintainer approval after the consensus activation freeze.
