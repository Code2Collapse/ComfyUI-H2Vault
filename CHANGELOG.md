# Changelog

## 0.1.3 - 2026-11-23

- Protect dialog: *Downloads for people who run it* lists the selection's model files and takes an https:// link for each; size and SHA-256 come from the author's own file at lock time (the protect route runs off the event loop while hashing). Live-checked in both renderers.

## 0.1.2 - 2026-11-23

- A vault prepares itself: missing model files download in the background under hash names (HTTPS only, resumable, size-capped, SHA-256 verified; public addresses only), missing extensions install from pinned commits; the browser sees counts and percentages only. Setting: Install automatically / Ask first / Never. Live-checked end to end on the testbed.

## 0.1.1 - 2026-11-23

- Concealed vaults show the current step in simple functional words ("Sampling", "Decoding", ...) and a step count on the vault node while they run; node names stay hidden (live-checked in both renderers and inside a subgraph).

## 0.1.0 - unreleased

First version of H2Vault as its own package.

### Added
- Protected subgraphs ("vaults"): `H2Vault_ProtectedSubgraph` and `H2Vault_ProtectedSubgraphOutput`. A selection, a
  group or a subgraph becomes one encrypted node that ComfyUI's own scheduler runs (native node expansion). Profiles:
  Sealed (authorized installations), Locked (password to run), Portable (obfuscation only).
- One-step protect dialog with stage progress and exact rollback on failure; open / edit with password + TOTP second
  factor; access management (runners, editors, password change); consent install of missing custom node packs.
- Encrypted workflow files, ported from ComfyUI-Workflow-Encrypt (jtydhr88, AGPL-3.0): key shown once, Workflow-Encrypt
  compatible token, remembered keys, password mode, decrypt on Open / drag-and-drop.
- H2Vault menu, commands and settings (`h2vault.protect.defaultProfile`, `h2vault.workflow.rememberKeys`).

### Derived from the C2C Vault (ComfyUI-CustomNodePacks, Apache-2.0)
- Envelope (Argon2id + AES-256-GCM, X25519 install wraps) with H2Vault's own magic `H2VAULT` and key-derivation domain
  strings; the C2C Vault's first format and its legacy nodes are not included.
- Changed: password lockout and one-KDF-at-a-time on every password route; second-factor setup and the consent install
  answer only the ComfyUI page on the same machine; custom-node requirements are never pip-installed.
