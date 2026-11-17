# JUAN VPN: HJ01 security audit

## 1. What was built and verified
New file format **HJ01** (`app/src/main/java/com/juanvpn/app/HJ01.java`), pure Java, tested on a JVM.

- Envelope encryption: random 256-bit data key per file, AES-256-GCM, fresh random 96-bit nonces, 128-bit tag.
- Password slot: Argon2id (default 64 MiB, t=3, calibrated per phone, minimum 19 MiB / t=2 enforced) then HKDF-SHA-256 then AES-256-GCM key wrap. Random 16-byte salt per file.
- Device / recipient slot: ephemeral ECDH P-256 against a public key, HKDF-SHA-256, AES-256-GCM key wrap. On the phone the private key lives in the Android Keystore (`HJDeviceKey.kt`).
- Up to 4 slots per file (password + several devices = authorized migration).
- Header fully authenticated: the payload tag covers the whole header and every slot; each slot is also bound to the core header.
- Strict parser: bad magic, version, algorithm/KDF id, flags, slot type, truncation, trailing bytes, hostile Argon2 sizes all rejected before any hashing.
- Wrong password and tampering return one generic error (no oracle) and never return data.
- Export self-verifies (re-parse, re-decrypt, re-open password slot) before returning the file.
- App side (`HJGuard.kt`): wrong-password delays (none for 3 tries, then 5 s doubling to 15 min, per file and global), optional per-file import limit, expiry check, Argon2 calibration cache.
- Transport: file text is `HJ01.` + base64url of the binary container, so export, share, cloud and config-code paths work unchanged.
- Legacy JSON .HJ (v1/v2) is **import only**, with the same attempt delays. Nothing new is written in that format and it never touches HJ01.
- Android: FLAG_SECURE while the unlock dialog is open; WebView no file/universal access, no mixed content, bridge reachable only from the bundled page; backup off (already); unused `MainActivity` no longer exported.

**Test result (security-tests/run.sh): 48 passed, 0 failed.** Includes: correct/incorrect password, flipping every single byte of the file (221 positions, 0 accepted), every truncation length, modified ciphertext/tag/header, bad version/algorithm/KDF downgrade, hostile Argon2 memory value, unique nonces/salts/file ids over 40 files, expiry (and that the expiry field is authenticated), device-bound file rejected on another device, device-id spoofing fails cryptographically, multi-slot migration, weak-parameter refusal. CI runs them on every push (job `security-tests`).

## 2. NOT verified (be aware)
- The Kotlin/Android glue (HJConfig, HJGuard, HJDeviceKey, JuanWebActivity, UI JS) and the APK were **not compiled or run** here: this sandbox has no network, Gradle or Android SDK. GitHub Actions will compile it; test export/import on a real phone before releasing.
- Keystore device binding is untested on real hardware. It needs Android 12+ (API 31); on older phones it is unavailable and passwords still work.
- No release APK exists, so the APK secret scan was done on the **source tree** only (no embedded keys, tokens or master secrets found; the only hit was the public alphabet used for cloud keys).

## 3. Requested but not done
- Biometric authorization (needs a prompt flow and a dependency I could not test).
- UI screens for device export / recipient picking / expiry / import limit. The bridge calls exist (`deviceKeyInfo`, `makeHJForDevice`, `deviceRevoke`); the screens do not.
- Cloudflare changes (authenticated uploads, rate limiting, short-lived tokens, revocation). I did not modify `cloud-server/worker.js` or D1: I cannot test it against Cloudflare and you asked me not to risk existing data.
- Server-side replay protection and revocation (a client-only app cannot do these honestly).
- Clipboard hardening and crash-report scrubbing were not audited in depth.

## 4. Findings in the existing project
1. **Cloud keys are weak.** An 8-character key (about 2^47) is hashed with a single SHA-256 to make the lookup token, and the same key encrypts the file. Anyone who can read the D1 table can brute-force the token offline and then decrypt that file. Fix: longer random keys (16+ chars) and a slow KDF for the lookup token. This changes the share-link format, so it needs a coordinated app + worker release.
2. **Anonymous uploads.** `/api/put` needs no authentication and has no rate limit, so anyone can fill your D1 database. Add Cloudflare rate limiting and an upload token.
3. **Release APK is signed with the debug key**, and `app/debug.keystore` (password `android`) is committed. Anyone can re-sign a modified APK. `build.gradle.kts` now uses a real key if you set `JUAN_KEYSTORE`, `JUAN_KEYSTORE_PASSWORD`, `JUAN_KEY_ALIAS`, `JUAN_KEY_PASSWORD` (keep the keystore outside the repo). Warning: a new signing key means current users must uninstall before updating.
4. `JuanPolicy` device-ID and operator locks are plain fields inside the config. They stop normal users, not a modified APK (the code already says so). Real device binding is the new HJ01 device slot.
5. An unlocked .HJ file is readable by design. Obfuscation (R8) is on for release but is not a substitute for encryption.

## 5. Limits that cannot be removed
- Offline guessing of a copied file is slowed only by Argon2id and the password strength. Use long passwords.
- Import limits, expiry and attempt delays are enforced by the app on the phone: a modified APK, a changed clock or a reinstall can get around them. One-time import does not stop copying after decryption.
