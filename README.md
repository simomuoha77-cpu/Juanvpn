# JUAN VPN — Android starter

This repository is a **buildable Android configuration/UI starter**, not yet a working VPN tunnel.

## Included
- Android app shell branded JUAN VPN.
- Manual SSH/proxy configuration fields.
- JSON configuration import/export through Android's document picker.
- GitHub Actions workflow that builds and uploads a debug APK.

## Not implemented yet
- SSH authentication/session and server host-key verification.
- SSH-over-TLS socket transport.
- Local HTTP CONNECT / SOCKS5 proxy listeners.
- Android `VpnService` TUN interface and packet forwarding (TUN-to-SOCKS).
- Secure credential storage and production-grade configuration encryption.

The connect button deliberately does not claim to connect. Do not distribute this APK as a functioning VPN.

## Build
Push this repository to GitHub on branch `main`, then open **Actions**.
The workflow builds `app/build/outputs/apk/debug/app-debug.apk` and uploads it as an artifact.

## Security requirements for the tunnel implementation
1. Verify SSH host keys (known_hosts or pinned fingerprints); never disable host-key checking.
2. Store secrets using Android Keystore-backed encryption; never export passwords in plaintext.
3. For TLS, validate certificate chains and hostnames; do not use trust-all managers.
4. Implement SSH forwarding and a maintained TUN-to-SOCKS engine before enabling `VpnService`.
5. Provide a persistent foreground notification, reconnect handling, DNS handling, IPv4/IPv6 policy, and leak tests.
6. Use only servers and networks for which you have authorization.

## Configuration format
Example only; do not commit real credentials:
```json
{
  "host": "vpn.example.com",
  "port": 22,
  "username": "your-user",
  "password": "",
  "httpProxyHost": "",
  "httpProxyPort": 0,
  "sshOverTls": false
}
```
