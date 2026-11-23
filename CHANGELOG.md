# Changelog

## Unreleased

**Authentication policies (L9.343, owner 2026-11-24)** - a vault can need ANY one or ALL of its chosen second factors
(all 14 combinations, docs/AUTH_POLICY.md), stored inside its encryption; vaults locked before keep exactly their
behaviour (an OR policy is still written in the old format). Recovery codes never replace the vault password; under
AND they are refused unless the author chose "may replace ONE missing factor" or "emergency override". Every factor
of a request is checked before anything is used up (a failed AND never burns a code), a wrong request counts once.
Opening says which authenticator / passkey was used. Policy builder with a plain-words preview and the registered
apps (+ *Add another authenticator*); per-vault "only particular authenticator apps". Enrolment: the server waits for
"I saved the recovery codes"; recovery codes are managed explicitly (`begin_enrolment(recovery=auto|new|keep)`, *New
set* warns first). Second factor dialog: added / last-used dates, last activity, which vault accepts what, backup
password last use, passkey kind (this device / security key). `H2VAULT_MAX_AUTHENTICATORS` (up to 50). Evaluation of
further methods: docs/AUTH_OPTIONS_EVALUATION.md.

**Previews from inside a vault (owner 2026-11-23)** - every preview an inner node produces shows on the vault node:
images through ComfyUI's own preview (merged, all preview nodes together), videos / audio / text in a new *Previews from
inside* panel, live sampler frames (also KJNodes Model Preview Override), the running step's progress, and the previews
of a cached run. Labels are "Preview N" or the author's own names, never inner names. New lock-dialog setting *Show
previews from inside on the vault* (default on, stored inside the encryption; *Previews on the vault…* in an open
vault). VHS `fullpath` and KJNodes' sigma schedule are no longer passed to the browser for inner nodes.

**Vault outputs when locking with concealment** - "Lock as a vault" no longer refuses a subgraph with no way out:

- A `*` (any-type) output is judged by what really reaches it: it is traced through pass-through nodes (Lazy Switch,
  any-switches, reroutes) to the nodes that make the value. Masks, images and other data pass; an output that can
  carry a model is refused; one that cannot be traced is allowed, because the vault checks it when it runs.
- Model outputs are recognised beyond the core types (`SEC_MODEL`, `SAM_MODEL`, detectors, pipes, `WANVAE`, ...).
  `SAM3_TRACK_DATA` is data (masks and scores only) and passes.
- When a concealed vault runs, every output is checked before it leaves the vault: a value that is or contains a
  model (a torch module, a ComfyUI model, CLIP or VAE) stops the run with a plain message naming only the output.
  This uses a hidden internal node, `H2Vault_OutputCheck`.
- Every problem in "Choose what to expose" names the output and offers fixes on its row: *Remove this output from the
  vault*, *Lock without concealment*, *Show it as MASK* (for a traced `*` output). Locking with problems left scrolls
  to and highlights the row; the notice goes away once the problems are fixed. A `*` socket is no longer called "*".

**One protection question, several authenticator apps (owner 2026-11-23)**

- **One question instead of checkboxes**: "How should this vault be opened for editing?" - *Password only*,
  *Password + authenticator app*, *Password + passkey*, *Password + backup password*, *Password + any second factor*
  (the default for a new vault) or *Advanced: pick methods*. Recovery codes stay an automatic fallback whenever a second
  factor is required. Old vaults show as the matching choice (no stored choice = authenticator app); a combination no
  plain answer fits shows as Advanced.
- **Password only** really opens with only the password: no second factor is asked, a factor sent anyway is neither
  checked nor used up, and no setup is required. It is weaker, and the choice says so. The open / access / licence
  dialogs now ask for the password first and for a second factor only when the vault needs one (`factor_required`, not
  counted as a failure); "set up a second factor" is asked after the password and only for such a vault.
- **Several authenticator apps**: up to 10 per installation, each named (add / rename / remove); a code of any of them
  opens, once per app; one wrong code is one failure however many apps exist; clock drift is detected for each. Each
  secret is its own secret-store entry (the Windows credential store keeps at most 2560 bytes per entry); the single
  secret of the first release becomes "Authenticator app" automatically (downgrading after that needs a new setup).
- **Second factor page**: every method with its state (set up / not set up / not possible here and why: passkeys on an
  IP address with an "Open as localhost" button, email and SMS need an online provider) and one Add button each.
- **Safe removal**: removing a method a vault needs is refused (409) while that vault would have no accepted method
  left on this installation - the answer names the vault and the fix; with recovery codes left it is allowed after a
  warning; removing the last authenticator app also asks for one more proof. The installation keeps a small note of
  the vaults it locked or opened (`<user dir>/h2vault/second_factor_vaults.json`: ids, titles, method names - no secret).

**Second-factor methods (owner 2026-11-23)**

- **No more "save password?" prompts**: vault password boxes are masked text inputs with the opt-out attributes of the
  common password managers (Chromium offered to save after every lock, open, run unlock and licence step because a
  password field disappeared after a successful request). Browsers that cannot mask text keep type=password.
- **Locked vaults ask once per tab, also across a reload**: the server keeps a tab's run keys for 2 minutes after the
  tab unloads and the reloaded tab (same client id) takes them back; after a ComfyUI restart the run asks again instead
  of failing.
- **Recovery codes can be entered**: "Recovery code" is a method of its own in every second-factor prompt; the answer
  says how many are left and offers a new set when few remain. H2Vault menu › Second factor › Generate a new set (shown
  once, .txt download). Stored as salted scrypt hashes now (older SHA-256 sets keep working until replaced).
- **More second factors, chosen per vault**: passkeys / security keys / Windows Hello (WebAuthn, verified with the
  `cryptography` package - no new dependency), a backup password, recovery codes, next to the authenticator app. The
  lock dialog, Lock parameters and Manage access have "Second factor for editing"; recovery codes are always accepted.
  Vaults locked before keep accepting the authenticator app + recovery codes. The prompt offers only what the vault
  accepts and is set up here, starting with the method used last. Email / SMS are not offered (they need an online
  provider).
- Lockouts grow: wrong passwords and wrong second factors wait 5 minutes after 5 failures, then twice as long each time
  (max 1 hour); second-factor failures count per vault and across vaults.
- Lost every method: `H2VAULT_RESET_SECOND_FACTOR=remove-all` at start removes the methods (nothing else).

## 0.2.0 - 2026-11-23

**Zero information (V8)** - a concealed vault tells nobody (and no AI reading the page, the logs, the history or the
outputs) what is inside:

- Files saved or previewed inside any vault (PNG text chunks) carry no workflow and no prompt; nodes outside a vault are unchanged.
- The step count of a concealed vault counts kinds of work ("Sampling", "Decoding", ...), no longer inner nodes; a concealed error names only the kind of step that failed.
- Log files ComfyUI writes itself (`--verbose LEVEL FILE`) get `[H2Vault] concealed output` for lines written inside a concealed vault, like the console and the log panel.
- Model lists (`/object_info`, `/models`, `/experiment/models`, `/embeddings`, `/api/assets`) never show the hash-named model copies a vault downloaded; their safetensors metadata and previews are not served.
- Installing a vault's missing extensions never repeats git's error text or a folder path (both name the extension).
- A warning core prints while it prepares an inner node of a concealed vault (for example a missing file found while checking whether the node changed) becomes `[H2Vault] concealed output` too.
- A plain vault that reuses the node id of an earlier concealed vault is no longer half-treated as concealed.
- Per-node routes of a co-installed pack (the Tensor Inspector of ComfyUI-CustomNodePacks) no longer list or describe nodes inside a vault.
- Lock parameters: without *Show what kind of node*, a node whose title is still its kind ("Load Checkpoint") is shown as *Locked node*.

**Lock parameters and licences (V5)**

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
- The author key backup restores on the author's new computer (that installation is not an editor yet); issuing and
  backing up again there work because it holds the author key.
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
