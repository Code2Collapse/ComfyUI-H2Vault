# Opening a vault for editing: authentication policies (L9.343, 2026-11-24)

Plain words first: every H2Vault that is opened for editing needs its **vault password**. The author can also ask for
a **second factor** - a code from an authenticator app, a passkey / security key / Windows Hello, or a backup password.
With this change the author decides whether the editor needs **any one** of the chosen factors (OR) or **all** of them
(AND), what a recovery code may do, and (advanced) which authenticator apps count. The choice is stored inside the
vault's encryption. Running a vault is never affected: only opening it for editing, managing its access and the
licence / author-key actions that already ask for the second factor.

Honest scope (unchanged): the second factor is enforced by the H2Vault code on the editor's installation; it protects
editing against other users of that ComfyUI and casual access, not against someone who controls that installation.

## 1. Where things live

| What | Where | Secret? |
|---|---|---|
| The vault's policy | `plain["second_factor"]` inside the vault's encryption | no (but private to the vault) |
| Authenticator apps | secret store, one entry per app `totp_auth_<id>` + index `totp_authenticators` | yes (TOTP seed) |
| Passkeys, backup password, recovery codes | secret store (`webauthn_credentials`, `backup_password`, `totp_recovery`) | public keys / scrypt hashes |
| Which vaults need what (for removal warnings) | `<user dir>/h2vault/second_factor_vaults.json` | no |
| Last authentication activity | `<user dir>/h2vault/second_factor_activity.json` (last 10 events) | no |

APIs, logs and the front end never see a TOTP seed, a passkey private key (H2Vault never has one), a backup password or
a recovery code after it was shown once.

## 2. The policy record

```
{"methods": [...], "mode": "any" | "all", "recovery": "fallback" | "off" | "replace_one" | "override",
 "authenticators": ["<app id>", ...], "v": 2}
```

* `methods` - the chosen factors among `totp`, `passkey`, `backup_password`. For an OR policy whose recovery rule is
  `fallback`, `"recovery"` is also listed - exactly the format before this change.
* `mode` - `any` (OR): one chosen factor is enough. `all` (AND): every chosen factor is needed.
* `recovery` - see section 4.
* `authenticators` (advanced) - only these authenticator apps of the sealing installation count as `totp`.

**Storage rule (no format break).** An OR policy with recovery `fallback` and no app restriction is written in the old
shape `{"methods": [...]}` - byte-for-byte what the previous release wrote, so every earlier H2Vault reads it the same.
Only AND, recovery `off` or an app restriction write `v: 2` and the extra keys.

**Reading (migration).** Old records map to the equivalent policy, nothing is rewritten on open:

| Stored | Policy |
|---|---|
| no `second_factor` (vaults before methods existed) | OR over authenticator app, recovery `fallback` |
| `{"methods": []}` | password only |
| `{"methods": [...]}` | OR over the listed factors, recovery `fallback` |
| `{"methods": [...]}` with an unknown method | OR over authenticator app + recovery (as before) |
| a `v: 2` record that does not read, or an unknown `v` (a newer format) | ALL of the three factors, recovery codes off (never weaker; update H2Vault) |
| `v: 2` record | as written |

An edit keeps the record unchanged; Manage access may change it (that re-encrypts the vault).

Known limitation: an editor installation still on the previous H2Vault reads only `methods` of a `v: 2` record and
applies OR to it. Update every editor installation before relying on AND policies.

## 3. The 14 combinations

| # | Combination | Policy |
|---|---|---|
| 1 | Password only | `methods: []` |
| 2 | Password + one (specific) authenticator | `totp`, OR, `authenticators: [id]` |
| 3 | Password + any registered authenticator | `totp`, OR |
| 4 | Password + passkey | `passkey`, OR |
| 5 | Password + backup password | `backup_password`, OR |
| 6 | Password + authenticator OR passkey | `totp, passkey`, OR |
| 7 | Password + authenticator OR backup password | `totp, backup_password`, OR |
| 8 | Password + passkey OR backup password | `passkey, backup_password`, OR |
| 9 | Password + any enabled second factor | all three, OR |
| 10 | Password + authenticator AND passkey | `totp, passkey`, AND |
| 11 | Password + authenticator AND backup password | `totp, backup_password`, AND |
| 12 | Password + passkey AND backup password | `passkey, backup_password`, AND |
| 13 | Password + all selected second factors | the chosen factors, AND |
| 14 | Advanced custom | any factors x OR/AND x recovery rule x app restriction |

The lock dialog offers 1, 3, 4, 5 and 9 as one-click answers (as before) and "Advanced: build a policy" for the rest.

## 4. Recovery codes (decision; owner may revise - see the report of L9.343)

A recovery code is single use and **never replaces the vault password**: the password is checked first, and a wrong
password neither looks at nor uses up a recovery code.

* **OR policies** - `fallback` (default, as before): a recovery code counts as the one factor. `off`: not accepted.
* **AND policies** - the default is `off`: a recovery code is **not** accepted, so AND is never silently weakened.
  The author may opt into one of:
  * `replace_one` - "a recovery code may replace ONE missing factor": the editor gives every other chosen factor plus
    one recovery code. With two chosen factors this means password + one factor + recovery code. Refused with ONE
    chosen factor (it would be an override in disguise - choose `override` explicitly).
  * `override` - "emergency override": password + a recovery code alone open the vault. The dialog says plainly that
    this makes the vault as strong as an OR policy with recovery codes.
* A recovery code that is not needed (every factor was given; under OR, another accepted factor was given) is not
  used up.

Losing every method of an AND vault with recovery `off`: the administrator reset
(`H2VAULT_RESET_SECOND_FACTOR=remove-all`) removes the methods of the installation; set new ones up and the vault
opens again, because a policy names kinds of factors, not particular devices - except an app restriction (2 / 14),
which names particular apps and then cannot be met any more. The lock dialog warns about that.

## 5. Checking a request

A request carries the password plus `factors: [{method, ...}, ...]` (new), `factor: {...}` (previous release) or
`code` (first release). Order of checks:

1. Password (counted per vault; a damaged payload is a 400, never a counted guess).
2. Password only -> done; factors sent anyway are ignored (never checked, never used up).
3. No method set up on this installation -> "set one up" (not counted).
4. Which factors are needed; a missing one -> `factor_required` with the missing list (not counted). A method the vault
   does not accept -> `method_not_allowed` (not counted).
5. Every given factor is **checked without side effects** first. Any wrong factor -> ONE counted failure for the
   request (per vault and install-wide, exponential lockout as before); with several factors the answer does not say
   which one was wrong. A re-used TOTP code -> `reused` (not counted).
6. Only when all pass are the side effects committed together: the app's last time step, the recovery code used up,
   the passkey's signature counter, the last-used dates and the activity note.

TOTP: every registered (or, with a restriction, every listed) app is tried, each with its own last accepted time step;
the first app whose code is fresh is used and named in the answer (`used: [{method, label}]`), never its secret.

## 6. Authenticator registrations

* Enrolment is per installation (default) and reused by every vault; a vault never shows a new QR code. The advanced
  app restriction is the per-vault option: "Add another authenticator" in the policy builder enrols a new app and ticks
  it under "Only particular authenticator apps" for this vault.
* First setup: QR + manual key -> a current code must verify -> recovery codes are shown and the server refuses the
  confirmation until the page says they were saved.
* Recovery codes are managed explicitly: `begin_enrolment(recovery="auto" | "new" | "keep")`. "auto" (default) creates
  a first set only when none remain (the previous behaviour, now named); "new" replaces the set when the new app is
  confirmed; "keep" never touches it. "New set" in the Second factor dialog warns first ("N codes stop working") and
  needs `confirm` on the server.
* Limit: 10 apps per installation by default, `H2VAULT_MAX_AUTHENTICATORS` up to 50. Each app is its own credential
  store entry (< 400 bytes); the index holds only ids (~15 bytes each, 50 -> < 1 KB), so no entry grows past the
  Windows credential store's 2560-byte limit (long values are split anyway, `secrets_store`).

## 7. Changing methods: step-up (review finding, 2026-11-24)

The Second factor dialog needs one proof before any change. Without more, one factor could replace another: with only
the authenticator app, set a NEW backup password, then open an "app AND backup password" vault. So the settings token
remembers WHAT was proven, and adding, replacing or removing a method kind K (authenticator app, passkey, backup
password, recovery codes) needs proofs that would themselves open every vault this installation knows that accepts K
and can be opened here today (`twofactor.step_up_vaults`, `check_manage(token, change=K)`). The dialog then asks
"Confirm once more" (each proof is added to the same session, `POST /h2vault/2fa/manage/begin` with the token). The
same rule makes OR vaults stricter than before: a backup password no longer lets you add an authenticator app to an
installation whose vault accepts only apps - prove with an app or a recovery code.

Limits (honest): only vaults this installation locked or opened since 2026-11-23 are known; a vault that cannot be
opened here today is not guarded (its missing factor is set up by whoever owns this installation); the first setup
session (nothing set up) and the administrator reset are not guarded, as before.
