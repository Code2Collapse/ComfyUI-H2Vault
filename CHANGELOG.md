# Changelog

## Unreleased - V8 zero information

- Files saved or previewed inside any vault (PNG text chunks) carry no workflow and no prompt; nodes outside a vault are unchanged.
- The step count of a concealed vault counts kinds of work ("Sampling", "Decoding", ...), no longer inner nodes; a concealed error names only the kind of step that failed.
- Log files ComfyUI writes itself (`--verbose LEVEL FILE`) get `[H2Vault] concealed output` for lines written inside a concealed vault, like the console and the log panel.
- Model lists (`/object_info`, `/models`, `/experiment/models`, `/embeddings`, `/api/assets`) never show the hash-named model copies a vault downloaded; their safetensors metadata and previews are not served.
- Installing a vault's missing extensions never repeats git's error text or a folder path (both name the extension).
- A warning core prints while it prepares an inner node of a concealed vault (for example a missing file found while checking whether the node changed) becomes `[H2Vault] concealed output` too.
- A plain vault that reuses the node id of an earlier concealed vault is no longer half-treated as concealed.
- Lock parameters: without *Show what kind of node*, a node whose title is still its kind ("Load Checkpoint") is shown as *Locked node*.

## 0.2.0 - 2026-11-23

- **Lock parameters**: right-click a node, a selection or a group > Lock parameters. Each node becomes a one-node vault
  drawn like itself (title, colours, sockets); ticked values are encrypted, the others stay editable controls. Every
  value is locked by default; the setting names and the node's kind are shown only if the author ticks it (otherwise
  errors also name only the vault). Locked values are blanked in errors, progress text, text outputs, history and the
  server log while the node runs. Nodes locked together unlock with one password prompt per tab. *Unlock parameters
  (remove protection)* restores the node (password + authenticator).
- **Licensed profile** (envelope version 2, mode 3; existing vaults unchanged): one public workflow, one offline
  Ed25519-signed licence per installation carrying the vault's licence key wrapped to that installation. Stops casual
  sharing of the workflow file; it is not copy protection (one licence key per workflow, shared by its licensees, who
  can extract it). Issue, add, revoke (new licence key + re-issue; run limits restart), *Licences issued* overview,
  author key backup / restore (vault password + authenticator; a replaced key is saved to a dated backup first). The
  newest licence for a copy decides. End dates and run limits are honour-system and labelled so. No licence server,
  no network call. Protecting as Licensed is local-page only.
- Locked nodes are envelope version 3: H2Vault 0.1.x refuses them instead of running them without the blanking.
- Blanking: other number / string spellings; numbers only in the node's own messages; `print()` output through core's
  log interceptor; nothing carried over to the next prompt.
- *Save again with the same password* checks the password against the file it was opened from (and asks twice).
- Encrypted workflows: *Save workflow encrypted again (same key)*; the dialogs say that images rendered from a
  decrypted workflow carry it in their metadata.
- Every password field warns when the page is reached over plain http from another machine.
- *Remove protection* for any vault (it becomes an ordinary subgraph after password + authenticator).
- Ideas from ComfyUI-NodeEncrypt and ComfyUI-XLJworkflowCipher (credited in NOTICE; no code or text taken).

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
