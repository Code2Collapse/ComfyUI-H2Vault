# More secure authentication options - evaluation (L9.343, owner request 2026-11-24 Part 2 E)

H2Vault is local-first: a vault opens on the editor's own ComfyUI, often with no internet. Every method below is judged
by four questions: does it work offline, what does it really protect, what can go wrong for the user, and how much new
code (= new risk) does it need. Status words: IMPLEMENTED (in this release, tested), NOT IMPLEMENTED (with the reason).

| Method | Offline | Verdict | Status |
|---|---|---|---|
| Authenticator apps (TOTP, RFC 6238) | yes | keep; several named apps, any one accepted, one code once per app | IMPLEMENTED (before; improved here) |
| Hardware security keys (YubiKey, Titan ...) via WebAuthn | yes | strongest local factor: phishing-resistant, key never leaves the device | IMPLEMENTED (`webauthn_min`; "security key" kind added here) |
| Windows Hello / Touch ID (platform authenticator) | yes | good: bound to this computer's TPM / secure enclave, unlock by face / finger / PIN | IMPLEMENTED (same WebAuthn path; "this device" kind added here) |
| Platform passkeys synced by a phone / password manager | yes for the check (the phone talks to the browser over Bluetooth / caBLE, which may need internet for the tunnel) | acceptable; weaker than a hardware key because the passkey is synced to a cloud account | IMPLEMENTED (WebAuthn "any" kind) |
| External FIDO2 keys over USB / NFC | yes | = hardware security keys | IMPLEMENTED |
| Device-bound authentication | yes | = Windows Hello / platform authenticator above (a WebAuthn credential that cannot leave the device) | IMPLEMENTED |
| Challenge-response with a registered cryptographic key | yes | this is exactly what WebAuthn does (server challenge, signature by a registered public key, counter check). A separate home-made scheme (e.g. a key file signing a challenge) would add code without adding strength | covered by WebAuthn; no separate scheme |
| Encrypted recovery key file | yes | possible: a high-entropy secret in a file, encrypted with a passphrase. It is a recovery code with more entropy and a file to lose. Recovery codes (8 x 50 bits, scrypt-hashed, single use) already cover the need; a file adds a new storage format and a new place for secrets to leak (backups, cloud sync) | NOT IMPLEMENTED (no gain over recovery codes; revisit if the owner wants printable-free recovery) |
| Backup password | yes | weakest second factor (something you know, like the vault password), but useful for editors without a phone or key; scrypt-hashed | IMPLEMENTED (before; last-used date added) |
| Recovery codes | yes | single-use emergency codes; never replace the vault password; AND-policy behaviour is explicit (docs/AUTH_POLICY.md section 4) | IMPLEMENTED (rotation with a warning added) |
| Email codes | NO - needs a mail provider and a server that sends mail | ONLINE-ONLY, optional, never a replacement for a local method; would need a separate service the author runs and trusts | NOT IMPLEMENTED (shown in the Second factor dialog as "not possible here, needs an online service") |
| SMS codes | NO - needs a paid SMS provider | ONLINE-ONLY and the weakest option (SIM swap, interception); same as email | NOT IMPLEMENTED (shown as not possible offline) |
| Security questions | yes | rejected: guessable, researchable, stored answers are low-entropy secrets | NOT IMPLEMENTED by design |

## Why WebAuthn covers four rows

YubiKey, Windows Hello, platform passkeys and FIDO2 keys all speak the same browser API (`navigator.credentials`) and
the same verification (`nodes/webauthn_min.py`: ES256 / EdDSA / RS256 >= 2048 bits, origin + RP id + challenge +
user-presence + signature-counter checks). The only difference the author or editor cares about is WHERE the key lives,
so the passkey setup now asks for a kind and passes it to the browser as `authenticatorAttachment`:

* "This device (Windows Hello, Touch ID)" -> `platform`
* "Security key (YubiKey ...)" -> `cross-platform`
* "Any" -> no preference (the browser offers both and phones)

The kind is shown next to each registered passkey. Limits that stay: browsers allow WebAuthn only on a secure page with
a host NAME (`http://localhost:<port>` or https), never on an IP address; a passkey belongs to the address it was made on.

## If online methods are ever wanted

They must be a separate, optional service, clearly labelled "needs internet", never the only accepted factor of a
vault, rate-limited server-side, and they must never send a vault secret. Nothing in H2Vault sends anything today.
