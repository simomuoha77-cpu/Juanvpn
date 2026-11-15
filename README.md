# JUAN VPN Android

JUAN VPN is an Android SSH/proxy client foundation with a branded four-tab interface, encrypted profile storage, JSON import/export, notifications, and persistent connection logs.

## Build

GitHub Actions runs `gradle assembleDebug` and uploads `juan-vpn-debug-apk`.

## Included in this source package

- Home, Logs, Tools, and Help screens
- SSH profile fields (password or private key)
- Strict SSH host-key verification using a supplied verified `known_hosts` entry
- HTTP/SOCKS proxy profile fields and TLS/SNI configuration fields
- Encrypted Android profile preferences
- JSON profile import/export
- Foreground notification and session state reporting
- Persistent connection event log
- GitHub Actions debug APK workflow

## Important implementation status

This source package is **not yet a complete device-wide VPN**.

The current SSH component starts a local SOCKS5 listener and uses SSH `direct-tcpip` channels. The Android VPN consent prompt and foreground service do not route phone traffic by themselves. The native TUN-to-SOCKS5 bridge (for example, `hev-socks5-tunnel`) must be built for Android ABIs, packaged, started with the TUN file descriptor, and tested before claiming full-device routing.

The HTTP proxy/TLS/SNI fields are saved as profile data; an HTTP CONNECT / TLS proxy chaining transport is not yet implemented. The current connection mode selection is not yet a full protocol selector.

## SSH host key

Strict host-key checking is enabled. Obtain the host key and fingerprint from your server provider using a trusted channel. Do not blindly trust an unverified key. Paste the verified OpenSSH `known_hosts` line into the profile.

## Security

Only use servers you own or are authorized to use. Exported profile JSON may contain credentials; store it securely and delete it when no longer needed. Location permission is not requested because it is not required for SSH tunnel operation.


## Stability fixes in this source revision

- The WebView activity is the only launcher; the legacy native activity is no longer a second launcher.
- The obsolete legacy VPN service is no longer declared as a VPN service.
- Android 13+ notification permission is requested and awaited before the VPN consent flow.
- Duplicate Connect requests are rejected while a connection attempt is active.
- Connection-service logs are persisted through `AppLog` and restored when the activity/service starts.
- Fixed the WebView/native log feedback loop: native log callbacks now render without being written back as new native log events. UI-originated log entries are persisted directly, preventing recursive duplicate timestamps and runaway log output.
- Kept the targeted Android packaging exclusion for the duplicate multi-release OSGi manifest reported by GitHub Actions.

## Important validation status

These source changes address lifecycle and permission-flow defects visible in the supplied project. They do not prove that a remote SSH server accepts the credentials or that the native TUN engine works on a particular device. A release must still be built in GitHub Actions and tested on a physical Android device with an authorized SSH server. The native engine must be packaged for the device ABI, and the TUN-to-SOCKS forwarding path must pass an end-to-end traffic test.


## Version 2.1.0 changes

- **520 / flaky connects:** temporary failures (proxy 5xx incl. 520-524, dropped handshakes, timeouts) are retried with a growing, randomised pause. Settings → Reliability (Auto reconnect, Delay, Max retries) now actually controls this. Credentials and host-key errors are never retried.
- **Direct + SNI (TLS):** new *Connect from* option. Connects straight to the SSH host (or an optional front address) over TLS with the server name you choose. *Verify certificate* is now honoured (on by default; turning it off logs a warning).
- **Shadowsocks** (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305; optional v2ray-plugin style WebSocket/TLS) and **V2Ray / Xray** (VLESS and Trojan over TCP, TLS or WebSocket) are implemented in `JuanXEngine.kt`. Paste `ss://`, `vless://` or `trojan://` links under *Proxy server → Import*.
- **VMess** (AEAD, alterId 0, AES-128-GCM) is supported over TCP, TLS or WebSocket on any port; the phone clock must be accurate.
- **Not available:** REALITY, XTLS flow, gRPC/HTTP2 transports and Hysteria (needs a QUIC stack). These are refused with a clear message instead of failing silently.
- **Log colours:** errors red, warnings amber, successful steps and *Connected* green.
