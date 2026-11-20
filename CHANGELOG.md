# Changelog

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
