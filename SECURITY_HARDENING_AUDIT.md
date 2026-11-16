# JUAN VPN security hardening audit — 2026-11-16

## Scope
Reviewed the supplied Android project and its Cloudflare Worker/D1 source. This patch is deliberately limited to changes that can be made safely without inventing subscription/account policy or changing existing cloud data.

## Changes in this patch
1. New locked HJ exports use envelope version 2.
2. AES-256-GCM authenticates the format/version, lock state, KDF identifier, PBKDF2 iteration count, salt, and nonce as associated data.
3. Version 1 locked HJ files remain importable for backward compatibility.
4. Unlocked HJ imports reject any encrypted-envelope fields, preventing a simple `locked=false` downgrade.
5. The Android cloud client now defaults to `https://juanvpn.juanvpn.workers.dev`.
6. Android version incremented to 2.9.3 (versionCode 22).

## Existing implementation observed
- Locked HJ export already used AES-256-GCM, random 16-byte salt, random 12-byte nonce, and PBKDF2-HMAC-SHA256 (310,000 iterations).
- Credentials were stored using AndroidX EncryptedSharedPreferences / Android Keystore.
- Release build already enabled R8 minification and resource shrinking.
- Cloud uploads encrypted the configuration on-device and stored ciphertext in D1.
- The Worker already checked input shapes, expiry dates, and HTTPS was required by the Android cloud client.

## Still missing or incomplete — do not claim hardened yet
- No trusted subscription entitlement service, signed authorization tokens, revocation, or bounded offline lease exists.
- HJ owner expiry in `JuanPolicy` is enforced using `System.currentTimeMillis()` on the phone; it is not trusted server time.
- Play Integrity is not integrated or verified server-side. The UI explicitly labels device attestation unavailable.
- Root detection is a basic filesystem/build-tag check. Runtime hooking, instrumentation, debugger, and APK certificate checks are not comprehensive.
- Cloud `/api/put` and `/api/get` rely on possession of an 8-character key-derived token. The Worker source has no per-IP rate limiter, account/device authorization, or revocation endpoint. Cloudflare deployment alone does not add these controls.
- The Worker health endpoint could not be independently reached from this build environment; successful live deployment is not verified.
- Crash handling stores stack traces and native diagnostics; log redaction must be completed and tested before production.
- The project has no automated security attack-test suite covering the 18 acceptance scenarios.
- Release signing currently uses the debug keystore. A private production signing key and Play App Signing/release process are required.
- The supplied manifest exposes multiple entry points and deep-link/import surfaces; all must continue to funnel through the same strict HJ validation path and need instrumentation tests.

## Cloudflare configuration still required
- Confirm the deployed Worker matches `cloud-server/worker.js`.
- Confirm the D1 binding is named `DB` and points to the existing `juanvpn` database.
- Add Cloudflare edge rate limiting for `/api/put` and `/api/get/*` before public release.
- Configure Worker secrets and a server-side authorization design before adding subscription enforcement. Never place private signing keys in the APK or commit them.
- Test the live `/api/health`, upload, download, expiry, and burn-after-import flows.

## Compatibility and release warning
This patch is source-level only. It has not been built with Gradle or tested on a physical Android device in this environment. Do not distribute it as a security-certified release until CI builds it and the attack tests pass. Version 1 HJ encrypted files are retained for compatibility; new exports use version 2.
