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
