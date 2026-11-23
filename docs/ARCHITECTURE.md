# H2Vault - architecture (workstream V2, 2026-11-20)

Status: DESIGN, written before the code (owner A7 rule). Repo: `D:/PROJECT/Custom_Nodes/ComfyUI-H2Vault`, branch
`dev`, remote `https://github.com/Code2Collapse/ComfyUI-H2Vault.git`. Licence AGPL-3.0 (owner answer 2026-11-20).
A copy of this file is committed in the repo as `docs/ARCHITECTURE.md`; this workspace copy is the one V3 reads.

## 1. What H2Vault is

A stand-alone ComfyUI custom-node package that protects workflows:

1. **Protected subgraphs** ("vaults"): a selection or a subgraph becomes ONE node whose inside is encrypted. ComfyUI's
   own scheduler runs the inside (native node expansion). Every capability of CNP's A18 "C2C Vault" is carried over.
2. **Encrypted workflow files**: the whole workflow saved encrypted and loaded back - a port of
   ComfyUI-Workflow-Encrypt (jtydhr88, AGPL-3.0), integrated with the H2Vault key store.
3. **A seam for model / node identity concealment** (workstream V3, section 7).

It needs no other Code2Collapse pack. Installing it next to CNP must not clash (section 5).

## 2. Where the code comes from

### 2.1 From CNP (Apache-2.0, `ComfyUI-CustomNodePacks`) - the A18 vault path only

| H2Vault module | CNP source | Change |
|---|---|---|
| `nodes/crypto.py` | `nodes/vault_crypto_v2.py` + `VaultError`, `boundary_hash` from `nodes/vault_crypto.py` | own magic `H2VAULT` and HKDF domain strings (`h2vault-v1 ...`); envelope version 1; same structure (Argon2id + AES-256-GCM, header as AAD, X25519 install wraps, portable wrap) |
| `nodes/protected_subgraph.py` | `nodes/secure_subgraph.py` | node ids, kill switch `H2VAULT_NATIVE`, messages; the v1 (`C2CVLT1`) branch removed |
| `nodes/routes.py` | `nodes/secure_subgraph_routes.py` + the `/c2c_vault/2fa/*` routes and the failed-attempt lockout of `nodes/vault_node.py` | routes `/h2vault/*`; v1 branches removed; lockout + one-KDF-at-a-time + off-loop KDF also on `open` and `access/open` (CNP only had it on `unlock_run`); local-UI guard on 2FA enrol / reset (section 6) |
| `nodes/twofactor.py` | `nodes/vault_2fa.py` | issuer "H2Vault" |
| `nodes/keys.py` | `nodes/vault_keys.py` | code prefix `h2vk1:` |
| `nodes/store.py` | `nodes/vault_store.py` | scope `vault` in the H2Vault secrets store |
| `nodes/secrets_store.py` | `nodes/_c2c_secrets.py` (backends only, no HTTP routes) | keyring service `h2vault:<scope>`; file backend at `<ComfyUI user dir>/h2vault/secrets.enc.json`; env `H2VAULT_SECRETS_BACKEND=file`, `H2VAULT_SECRETS_PASSPHRASE` |
| `nodes/packs.py` | `nodes/vault_packs.py` | kill switch `H2VAULT_INSTALL`; requirements are NOT pip-installed (CNP's `integrity_guard` installer is not vendored); the user is told to finish them in ComfyUI-Manager |
| `nodes/local_guard.py` | `nodes/_local_ui_guard.py` + `is_local_ui_origin` and helpers of `nodes/magnific/security.py` | inlined (no Magnific import) |
| `nodes/_vendor/qrcodegen.py` | `nodes/_vendor/qrcodegen.py` (Nayuki, MIT) | unchanged |
| `web/js/h2vault_vault.js` | `js/c2c_secure_subgraph.js` (V1 working copy, 2026-11-20 23:35) | names, routes, CSS prefix; legacy-node upgrade removed |
| `web/js/_h2v_protect_tx.js` | `js/_vault_protect_tx.js` | unchanged logic, header + names |
| `web/js/_h2v_ui.js` | `js/_vault_ui.js` (V1 design system) | `h2v-` classes, `--h2v-*` tokens on ComfyUI's theme variables |
| `web/js/_h2v_selection.js`, `_h2v_rebind.js` | `js/_vault_selection.js`, `js/_vue_dom_rebind.js` | H2Vault types only |

Not taken, on purpose (they exist in CNP only so that CNP saves made before A18 keep loading; H2Vault has no such
saves): `nodes/vault_node.py` (C2C_VaultLocked / Sealed / EditInput / EditOutput nodes, `/c2c_vault/*` legacy routes),
`nodes/vault_exec.py` (custom executor), `nodes/vault_promote.py`, `nodes/vault_boundary.py`, `nodes/vault_crypto.py`
v1 envelope (`C2CVLT1`, PBKDF2), `js/c2c_vault.js` (A17 front end), `js/_vault_flatten.js`. The shared CNP helpers
`_c2c_settings`, `_is_changed_util`, `integrity_guard`, `js/_c2c_compat.js`, `_c2c_runtime.js`, `_c2c_undo_scope.js`,
`_widget_visibility.js` are imported only by those legacy files, so none of them is vendored.

Every file taken from CNP keeps a header `# Derived from Code2Collapse ComfyUI-CustomNodePacks <path> (Apache-2.0)`
and NOTICE lists them. Direction is one-way: no H2Vault code ever goes into CNP (AGENT_RULES rule 3).

### 2.2 From ComfyUI-Workflow-Encrypt (AGPL-3.0, jtydhr88, `third_party/ComfyUI-Workflow-Encrypt` @ 5ec45fd)

Their feature: "Save (Encrypted)" -> server makes a Fernet key, encrypts `JSON(workflow)`, shows the key ONCE
(alert + server console), browser downloads `encrypted_data.txt` (the Fernet token). "Load (Decrypted)" -> prompt for
the key, pick the file, server decrypts, `app.loadGraphData`.

H2Vault port (`nodes/workflow_encrypt.py`, `web/js/h2vault_workflow.js`, `# PORTED FROM:` headers):

- **Format kept readable both ways.** The ciphertext is exactly their Fernet token of `json.dumps(workflow)`. H2Vault
  saves `<name>.h2vault.json` = `{"h2vault_encrypted_workflow": 1, "scheme": "fernet", "token": "<Fernet token>",
  "note": ...}` (JSON, so drag-and-drop / Open goes through ComfyUI's own loader and H2Vault's load hook asks for the
  key), and "Export for Workflow-Encrypt (.txt)" writes the bare token their extension loads. H2Vault loads both: the
  wrapper, and a bare token file made by Workflow-Encrypt.
- **Key shown once, never logged.** Their server printed the key to the console; H2Vault never logs it. The dialog
  shows it once with Copy / Download key file.
- **Key store integration (strictly better than a bare prompt):** "Remember this key on this installation" (default
  on) keeps the key in the H2Vault secrets store (OS credential store or the encrypted file), indexed by the token's
  SHA-256 fingerprint. Loading a file whose fingerprint is known decrypts without asking; otherwise the dialog asks for
  the key (paste, or load a key file). Remembered keys can be listed (labels + fingerprints, never the keys) and
  forgotten. All key-store routes are local-UI only.
- **Password mode** (carries over CNP's "Save workflow encrypted"): `scheme: "argon2id-aesgcm"` - Argon2id(password,
  salt) + AES-256-GCM with the header as AAD; nothing stored server-side.
- Not ported: their auto pip-install at import, the copy of JS into `web/extensions`, the legacy `.comfy-menu`
  buttons (the new frontend has no such menu). Entry points are commands, the top menu and the workflow menu.

## 3. Module map and dependencies

```
__init__.py              guarded imports per module; NODE_CLASS_MAPPINGS; WEB_DIRECTORY = "./web/js";
                         registers routes + the message filter only when PromptServer exists
nodes/
  crypto.py              envelope (no ComfyUI imports)            <- protected_subgraph, routes
  secrets_store.py       keyring / encrypted-file backends        <- store, workflow_encrypt
  store.py               scope "vault" facade (tests: BACKEND)    <- keys, twofactor
  keys.py                install X25519 identity                  <- routes, protected_subgraph
  twofactor.py           second-factor methods + lockouts         <- routes
  webauthn_min.py        passkey (WebAuthn) verification          <- twofactor
  packs.py               record / summarise / consent install     <- protected_subgraph, routes
  protected_subgraph.py  the two nodes, expansion, leak filter    <- routes, __init__
  routes.py              /h2vault/vault/*, /h2vault/2fa/*         <- __init__
  workflow_encrypt.py    encrypted workflow files + key store     <- __init__
  local_guard.py         loopback-page check                      <- routes, workflow_encrypt
  licence.py             V5 offline licences (Ed25519, install wraps), stores, author key   <- routes, protected_subgraph
  previews.py            inner previews -> the vault (merge, labels, author setting, cached replay)   <- protected_subgraph, concealment, routes
web/js/
  _h2v_ui.js             dialog kit + CSS (h2v-)                  <- the two below
  _h2v_protect_tx.js     protect transaction                     <- h2vault_vault.js
  _h2v_selection.js      what a protect acts on, stage labels    <- h2vault_vault.js
  _h2v_rebind.js         Nodes 2.0 DOM-widget rebind (extension "H2Vault.VueDomRebind")
  h2vault_vault.js       vault front end (extension "H2Vault.Vault")
  h2vault_workflow.js    encrypted files (extension "H2Vault.WorkflowEncrypt")
  _h2v_lockparams.js     V5 Lock parameters: lockable rows, the lock request (pure)
  _h2v_licence.js        V5 licence UI: terms, status lines, honour-system note (pure)
  h2vault_previews.js    the vault's 'Previews from inside' panel (extension "H2Vault.Previews")
  _h2v_previews_core.js  preview panel plan + 'Preview N' numbering (pure)
  _h2v_previews_ui.js    the author's preview setting (lock dialog, open vault)
tests/                   pytest (comfy_env python) + node --test for the .mjs
```

`_`-prefixed JS files are imported modules; ComfyUI loads every .js in WEB_DIRECTORY, so they register nothing.

## 4. Namespace plan

| Thing | CNP C2C Vault | H2Vault |
|---|---|---|
| Node ids | `C2C_SecureSubgraph`, `C2C_SecureSubgraphOutput` | `H2Vault_ProtectedSubgraph`, `H2Vault_ProtectedSubgraphOutput` |
| Category | `C2C/Vault` | `H2Vault` |
| Routes | `/c2c_vault/sg/*`, `/c2c_vault/2fa/*`, `/c2c_vault/workflow/*` | `/h2vault/vault/*`, `/h2vault/2fa/*`, `/h2vault/workflow/*`, `/h2vault/keys/*` |
| Settings | `c2c.vault.*` | `h2vault.*` (e.g. `h2vault.workflow.rememberKeys`, `h2vault.protect.defaultProfile`) |
| JS extensions | `C2C.SecureSubgraph`, `Code2Collapse.CustomNodePacks.Vault` | `H2Vault.Vault`, `H2Vault.WorkflowEncrypt` |
| Commands | `c2c.vault.*` | `h2vault.*` |
| CSS | inline styles / `c2c-` | classes prefixed `h2v-`, one `<style id="h2v-style">` |
| Node property | `properties.c2c_vault` | `properties.h2vault` |
| Payload magic | `C2CVLT2` | `H2VAULT` |
| Install code | `c2cvk1:` | `h2vk1:` |
| Key file | `.c2ckey`, format `c2c-install-key` | `.h2vkey`, format `h2vault-install-key` |
| Secrets | keyring `c2c-secrets:<scope>`, `user/c2c/secrets.enc.json` | keyring `h2vault:<scope>`, `user/h2vault/secrets.enc.json` |
| Env | `C2C_VAULT_NATIVE`, `C2C_VAULT_INSTALL`, `C2C_SECRETS_BACKEND` | `H2VAULT_NATIVE`, `H2VAULT_INSTALL`, `H2VAULT_SECRETS_BACKEND` |
| Window globals | `__c2cVaultNative` | `__h2vault` (browser tests only) |

Both packs patch `LGraph.prototype.serialize`, `copyToClipboard`, `app.graphToPrompt` and `api.queuePrompt`. Each
uses its own flag (`__h2vSerialize`, ...) and only touches its own node types, so the two chains compose. Each pack's
message filter rewrites only the inner ids of its own vaults (separate `_ACTIVE_VAULTS` sets).

## 5. Coexistence contract (tested)

`tests/test_coexistence.py` asserts, against CNP's source on disk when present: no shared node id, no shared route
path, no shared settings id, no shared JS extension name, no shared command id, no shared keyring service / user-dir
folder. A vault made by one pack is not openable by the other (different magic) - by design; a migration
"C2C Vault -> H2Vault" is backlog (section 9).

## 6. Security notes (threat model delta vs CNP)

Assets: vault inner graphs, the vault password, the install private key, the TOTP secret, recovery-code and backup
password scrypt hashes, passkey public keys,
remembered workflow keys. Boundaries: browser page <-> ComfyUI server (HTTP), server <-> secrets store, workflow
files leaving the machine.

- Same honest limit as CNP: a machine that runs a vault can read its inside (it must be plaintext to execute).
- Passwords / keys travel only over the routes, never in a widget, prompt, workflow, log or history.
- Password guessing: per-vault lockout (5 failures -> 5 min, then doubling up to 1 h) and a single KDF gate on EVERY
  password route (`unlock_run`, `open`, `access/open`); the KDF runs off the event loop.
- Second factor (2026-11-23): methods per installation (`twofactor.py`): TOTP, passkeys (`webauthn_min.py`: ES256 /
  EdDSA / RS256 assertions over authenticatorData || SHA-256(clientDataJSON), origin from the request's Host header,
  rpIdHash, user presence, counter; attestation not verified), backup password and recovery codes (scrypt, constant-time
  compare). A vault's accepted methods live INSIDE the ciphertext (`second_factor.methods`; default TOTP + recovery) and
  are checked after the password and BEFORE the factor, so a refused method is neither consumed nor counted. Wrong
  factors are counted per vault and across vaults (exponential, persisted). Changing methods needs a 10-minute settings
  token from one proof (local page only). `H2VAULT_RESET_SECOND_FACTOR=remove-all` at start removes every method (the
  administrator's way back; whoever can set it can already read the secret store).
- Routes that create or read local secrets without a vault password (2FA enrol begin / confirm / reset, the workflow
  key store) answer only the ComfyUI page on this machine (loopback peer + loopback Host + no cross-site
  Origin / Sec-Fetch-Site). Through an SSH tunnel the page still counts as local.
- Workflow-Encrypt keys: never printed; remembered keys are stored only in the secrets store; the list route returns
  labels and fingerprints only.
- Missing-node install: consent click, https on four known git hosts, pinned 40-hex commit, fresh folder only, no
  pip install.

## 7. V3 seam: model / node identity concealment

Owner: "no model names, no node / class names shown; only parameters, sampler, scheduler exposed". What a vault shows
in the clear today, and where V3 changes it:

| Exposure | Where it is produced | Seam for V3 |
|---|---|---|
| Promoted control names + values (e.g. `ckpt_name` = `sdxl.safetensors`) | front end `buildApi()` -> `interface.params` (`web/js/h2vault_vault.js`), stored in `properties.h2vault.interface` and in the `p_<key>` widget values of the prompt | `publicInterface(built)` in `h2vault_vault.js`: the single function that turns the extracted interface into what is written to the node. V3 adds a policy there (rename / drop / mask), plus the server-side check in `routes.py::_iface` |
| Socket names / types | same `interface.in / out` | same function |
| Error messages naming the inner node TYPE | `protected_subgraph.py::_sanitize_error` (`node_type`) | `protected_subgraph.public_node_type(vault_id, inner_type)` - today returns the type; V3 returns a neutral label |
| Missing-node message | already counts + hosts only | none needed |
| Progress / executing events | already mapped to the vault id | none needed |
| Node count on the badge | `properties.h2vault.node_count` | `publicInterface` |
| Model names inside the graph | encrypted (inside the payload) | none needed |

V3 owns new files (`nodes/concealment.py`, `web/js/_h2v_conceal.js`) and calls in at those two functions; it does not
edit the crypto or the transaction.

As built (V3, 2026-11-21): concealment is a MODE of a vault - a plaintext with a `conceal` section (title, alias
tables, declared previews) runs on the same node classes. `routes.protect` / `commit` / `snapshot` refuse a public half
that would name the inside and answer `public_interface` (a whitelist); `publicInterface(built)` returns it
(`built.public`), so the node, the saved workflow and the open-vault snapshot never carry real file names;
`applyInterface` builds concealed controls with `_h2v_conceal.js::ensureControl` and hides the node count.
`protected_subgraph.execute` resolves aliases server-side (`concealment.resolve_params`) and registers the expansion
(`concealment.after_expansion`); `__init__` installs `concealment.install(server)` after the vault message filter:
for a concealed vault no inner class, title, id, model file or author output prefix leaves the server (messages,
history, jobs, errors, the log buffer and console while an inner node runs). Hosted profile: env `H2VAULT_HOSTED=1`
(+ `H2VAULT_HOSTED_ALLOW`). Author side: the protect dialog's "Conceal models and nodes" step
(`web/js/_h2v_expose.js` pure inventory / roles / aliases / candidate, `_h2v_expose_ui.js` the step, preview drawn by
`_h2v_conceal.js::renderPreview` from `POST /h2vault/vault/conceal/check`, the same `check_public` as sealing; the
browser whitelist is `_h2v_public.js`). The author's exposure is stored in `conceal.controls` / `conceal.sockets` and
merged by `concealment.merge_exposure` on every seal, so an edit keeps it; with it present ONLY the author's controls
are exposed (frontend-auto-promoted widgets keep their value inside). `commit` with `conceal: null` removes
concealment; the front end asks the editor to confirm first. Design, threat model and residual risks:
workspace `docs/h2vault/V3_concealment_design.md`.

V8 (2026-11-23, zero information; audit: workspace `docs/h2vault/V8_zero_information_audit.md`): `after_expansion`
also notes vaults that are not concealed (`Concealer.register_plain`), and `concealment.install` adds three guards that
do not depend on a websocket message: `metadata_guard` wraps core `execution.get_input_data` so a node inside ANY vault
receives an empty `PROMPT` and no `EXTRA_PNGINFO` (no workflow in files written inside a vault; fails closed);
`WindowLogFilter` on the root handlers rewrites records formatted outside the log interceptor (core `--verbose LEVEL
FILE`) inside a Concealed Window; `hash_folder_middleware` (every profile) drops V7 hash-named copies
(`h2v/<sha256 prefix>.<ext>`) from model listings and refuses their `/view_metadata` and previews. `h2vault.phase`
counts distinct functional labels (one event per label change), and a concealed error carries the failing step's label.
`IsChangedCache.get` opens the Concealed Window while core computes an inner node's cache key (its IS_CHANGED warning
named inner files); `attach_root_filter` is the one root-logger attachment for V5's value redaction and V8's window
filter; the middleware also drops inner vault ids from per-node routes of co-installed packs (CNP Tensor Inspector).

## 8. Plug-and-play

- Install = clone or registry; `requirements.txt` = `cryptography>=42` (Argon2id needs >=44 - checked at import with
  a plain message), `keyring` optional. No torch pins.
- Entry points without hunting: right-click a selection (Protect), right-click a subgraph, the top menu "H2Vault",
  the command palette, and drag-and-drop of an encrypted workflow file.
- First vault: a fresh install has no second factor; opening a vault opens the Second factor dialog first.

## 9. Backlog (not in V2)

- Read C2C Vault (`C2CVLT2`) payloads and convert them to H2Vault (needs both domain strings; owner decision).
- Owner-hosted profile (CNP L9.49).
- Workflow-Encrypt file re-save keeping the same key ("relock").

## 10. Registry naming

Settled by workstream V4 (`docs/h2vault/V4_registry_naming.md` section 5): `[project] name = "ComfyUI-H2Vault"` (the
registry id is the install folder, case included, and permanent after the first publish; it matches the GitHub repo so
git clone, ComfyUI-Manager and comfy-cli installs give the same folder), `[tool.comfy] PublisherId = "code2collapse"`,
`DisplayName = "ComfyUI-H2Vault"`. JS never hard-codes `/extensions/ComfyUI-H2Vault/` (relative imports only).
Publishing is the lead's / owner's decision.

## V5 (0.2.0): Lock parameters and offline licences

Design and threat model: workspace `docs/h2vault/V5_enhancements_design.md`. A Locked node is a one-node vault with a
`lock` section in its plaintext (`routes._with_lock`; public part = title, colours, count, and the setting names / node
kind only when the author publishes them); `protected_subgraph.register_redaction` blanks its values in messages and the
log while its prompt runs (numbers only in its own messages; strings also in the server log via core's stdout /
stderr interceptor; state cleared per prompt). Locked-node vaults are envelope version 3 (v1 layout) so 0.1.x refuses
them. Licensed vaults are envelope version 2 / mode 3 (`crypto.py`: author Ed25519 key in the
header, a licence slot = the data key under the licence key); `licence.py` signs, verifies, stores licences and counts
runs; `protected_subgraph.open_licensed` -> `licence.best_for_run`: the newest licence that opens this copy decides
(no fall-back to an older one). Licences stop casual sharing; one licence key per vault is shared by its licensees,
so they are not copy protection. Author key backup / restore need a Licensed vault's password + authenticator.

## Previews from inside a vault (2026-11-23)

`nodes/previews.py`. Every `executed` ui output of an inner node is collected per vault and per run (`HUB.register` at
expansion, `HUB.collect` in both message filters: protected_subgraph for ordinary vaults, concealment for the declared
previews of a concealed vault) and sent to the vault id as ONE merged output: core's `images` (still / animated images,
drawn by core's own preview in both renderers) + `h2v_previews` (every item with its public label: the author's or
"Preview N" in `order_of(api)` order; files without VHS's `fullpath`; never a top-level `filename`, so the frontend's
result-item parsers skip it). `web/js/h2vault_previews.js` renders videos / audio / text and KJNodes'
`kj_preview_override` frames (whose `node_id` is the display id = the vault; the sigma schedule is stripped).
Live b_preview metadata already names the vault (display id + `_deep_map`). progress_state collapses per vault onto
the running inner step (`collapse_progress`). Cached runs: core sends the vault's own `executed` with `output: null`;
`install_replay` wraps `execution.execute` to note the vault's input-signature cache key (core's internal
`cache_key_set.get_data_key`, read-only, guarded) and the filter replays the previews stored under that key (history
too). The author's `previews: {show, labels}` lives inside the encryption; off = every inner executed / binary preview /
custom preview event naming the vault is dropped (progress stays), and only the bit `previews_off` is public on the node.
