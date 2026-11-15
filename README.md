# JUAN VPN — Android project

Professional Android client foundation for authorized SSH/proxy connections. Includes a branded native UI, SSH credential fields, encrypted local profile storage, JSON import/export, Android foreground notification, and GitHub Actions APK build.

## Build APK

GitHub Actions builds a debug APK on every push/PR and on manual dispatch. Open **Actions → JUAN VPN Android Build** and download the `juan-vpn-debug-apk` artifact.

Local build requires JDK 17 and Android SDK 35:

```bash
gradle assembleDebug
```

## Current implementation status — read before deployment

- Implemented: Android project, profile editor, encrypted preferences, JSON import/export, notification-backed service lifecycle, SSH authentication using JSch, and an SSH `direct-tcpip` SOCKS5 listener bound to `127.0.0.1`.
- Not implemented: full-device `VpnService` TUN packet capture and TUN-to-SOCKS5 forwarding. Android's VPN consent prompt and foreground service do **not** by themselves route device traffic. The UI currently starts the SSH-backed local SOCKS5 endpoint, not a complete device-wide VPN.
- HTTP proxy/TLS fields are currently profile data/UI only; an HTTP CONNECT/TLS transport engine is not yet wired into the SSH handshake.
- The SSH implementation requires the server's verified OpenSSH known_hosts line in the **VERIFIED SSH KNOWN_HOSTS LINE** field; strict host-key checking is enabled. Obtain and verify the fingerprint through your server provider or an independent trusted channel. Never blindly trust an unverified key.

Do not advertise this build as a complete full-device VPN until the packet-forwarding engine and end-to-end tests are integrated. Do not use third-party servers without permission.

## Permissions

`INTERNET`, `ACCESS_NETWORK_STATE`, foreground service, special-use foreground service, notification permission, and the system VPN service declaration are included. Location permission is deliberately not requested: a VPN client does not need device location merely to establish an SSH tunnel. Notification permission is requested by Android at runtime on Android 13+ when the app is updated to include the runtime prompt flow.

## Import/export

Profiles use JSON format `juanvpn-profile-v1`. Exported profiles contain credentials; keep exported files private and delete them when no longer needed.
