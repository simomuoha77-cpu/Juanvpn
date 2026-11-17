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


## VMess 2.2.3 response-header nonce fix

Fixes the VMess AEAD response-header KDF inputs: response-header keys are derived from the response body key, while response-header IVs are derived from the response body IV, matching Xray-core. Adds distinct response-header authentication errors and increments Android versionCode to 6 / versionName to 2.2.3.


## Version 2.3.0 — JUAN HJ config exporter

- Added an HTTP-Injector-style Config Exporter screen with SSH, V2Ray, Hysteria and Shadowsocks export flags; General, SSH, V2Ray, DNSTT and Extra policy fields; notes; and `.HJ` naming.
- Added `.HJ` import using Android's document picker, `.HJ` save to any Android document provider (including connected cloud-drive providers), sequential locked/unlocked export, and file sharing through Android Sharesheet.
- Locked `.HJ` files encrypt the complete profile (including payloads, server names, UUIDs, passwords and private keys) with PBKDF2-HMAC-SHA256 and AES-256-GCM. The GCM authentication tag detects file modification. A password of at least 10 characters is required and is never written to app preferences.
- Imported owner-locked profiles hide server/host/payload details in the app and disable editing while retaining the ability to connect. Individual export field-lock flags are preserved.
- Unlocked `.HJ` exports are intentionally readable and should be shared only when that is intended.
- Device attestation, root/Play Store/device-ID checks, expiry, operator lock, torrent filtering, gaming-only routing, Hysteria and DNSTT are metadata-only in this revision; they are not represented as active enforcement or working tunnel protocols.
- Client-side encryption protects locked config files, but cannot make an Android APK impossible to reverse engineer, patch or repackage. Strong app-integrity enforcement requires a private release-signing key and server-side verification (for example, Play Integrity).


## Version 2.4.0: Save to cloud (link + key + emoji key)

- **Config exporter** now has the floating menu (Save to cloud, Save, Save locked & unlocked, Save & Share) and an export summary dialog before saving.
- **Save to cloud** offers Normal, Burn after import and Set Expiry Date, then shows the cloud link, the 8-character key, the emoji key and a `juanvpn://import?...` app link, each with a copy button.
- **Import from cloud key** (Servers screen, exporter, or by tapping the link page / `juanvpn://` link) accepts the link, the key or the emoji key.
- Configs are encrypted on the phone (AES-256-GCM, key derived from the cloud key). The server stores only ciphertext under a hashed token.
- **You need your own server**: deploy `cloud-server/` (Cloudflare Worker + D1, free plan). See `cloud-server/README.md`. Set its address in Settings -> Cloud server, then tap Test server.

## Version 2.4.1

- The cloud result shows link, key and emoji key only (no app URI).
- **Config code (no server):** Config exporter -> *Copy config code*. Produces a `JUAN1:...` text that contains the whole config. Paste it in *Import from cloud key or code*. A cloud server is only needed for the short key / emoji key.

## Version 2.5.0

- **Import config** is now its own screen (Menu, Servers, or the + button): *Internal Storage* (opens the file picker) and *Cloud Config* (key, emoji key or `JUAN1:` code). The import buttons were removed from the exporter.
- **Save to cloud (code)** keeps Normal / Burn after import / Set Expiry Date, and now shows only the key and emoji key (no link).
- **Locked configs cannot be exported or opened in the exporter.**
- Set `DEFAULT_SERVER` in `JuanCloud.kt` to let users import keys without configuring a server.

## Version 2.6.0

- **No host-key prompt.** Server keys are accepted automatically; the fingerprint is only written to the log. Connecting never waits for confirmation.
- **Any payload.** Placeholders: `[host] [port] [host_port] [ssh] [protocol] [method] [netData] [raw] [realData] [crlf] [cr] [lf] [lfcr] [ua] [sni] [proxy] [path] [auth] [rotate=a;b] [random=a;b] [split] [instant_split] [delay_split] [delay=ms]`. Text after a blank line is now sent (decoy request + upgrade), replies to earlier requests are skipped, 101 or a 2xx to the last request opens the tunnel, an SSH banner arriving first is also accepted, any HTTP version and LF-only replies work, and a missing closing blank line is added.
- **Any proxy.** New *SOCKS4 proxy* (4a for names) and *Direct + Payload*. HTTP, SOCKS5, TLS and WebSocket stay. The proxy field accepts `http://user:pass@host:port`, `host:port` and `[ipv6]:port`. SOCKS5 sends IP literals as addresses.

## Version 2.7.0: rotation

- **Proxy rotation:** the Remote proxy field takes many entries (comma, space or new line separated). Each is `host`, `host:port`, `http://user:pass@host:port` or `[ipv6]:port` and can carry its own login.
- **SNI rotation:** the SNI field takes many names.
- **Payload rotation:** put several payloads and separate them with a line of `---`. The `[rotate=a;b;c]` and `[random=a;b;c]` tags still work inside one payload.
- Every connection starts at the next proxy / SNI / payload. When one is rejected (403, 421, 5xx, TLS failure, timeout) the app falls through to the next combination, up to 12 tries, before reporting an error.

## Version 2.7.1

- `[rotate=a;b;c]` and `[random=a;b;c]` now work as real fallbacks: every option is its own candidate. If the server rejects one (403, 421, ...) the app tries the next option in the same connect instead of stopping. Options may contain tags, e.g. `[rotate=GET / HTTP/1.1[crlf]Host: a[crlf][crlf];CONNECT [host_port] HTTP/1.0[crlf][crlf]]`.
- The log now shows the payload request line and Host header that was sent, so a rejected payload is easy to spot.

## Smart proxy rotation (v2.8.0)

SSH profiles with several proxies, SNI names or payloads now rotate automatically:

- Every proxy x SNI x payload combination is one candidate. The last combination that fully connected is tried first.
- Each candidate is tried once per cycle. If none works the app waits and starts a new cycle (cycles = Retries + 1 when auto-reconnect is on).
- A combination counts as working only after: TCP connected, HTTP/WebSocket reply (WebSocket mode needs **101**), SSH banner, SSH login, TUN started and the traffic check passed. Only then is the state CONNECTED and the combination saved.
- The saved record (`juan_rotation` preferences) holds proxy, mode, SNI, payload number/variant/hash, SSH server:port and a timestamp. No SSH or proxy passwords, and the profile itself is never edited.
- Failures are logged by kind: DNS, TCP timeout/refused, TLS, 301/302, 400/403, 5xx, invalid WebSocket handshake, proxy closed, SSH banner/timeout, SSH auth, TUN init, traffic check.
- Payloads are sent exactly as written (custom payloads, `[split]`, `[crlf]`, `[rotate=..]`, large Content-Length all unchanged). They are only refused when oversize (16 KB, 32 parts, 20 s of delay), contain a NUL byte, have a malformed request line, or contradict themselves (two different Content-Length values, or Content-Length with Transfer-Encoding). A refused combination is skipped and logged; nothing is rewritten.
- Disconnect cancels any attempt in progress, and a new connect waits for the cancelled worker, so two workers never run together.

## Version 2.9.0

- **Reconnect after airplane mode / network change.** While connected the service watches the network. When the network is lost (airplane mode on, no signal) or the SSH connection drops (wifi <-> mobile data), JUAN VPN waits for the network, then opens a brand-new tunnel session by itself, using the last working proxy combination first. The old TUN stays up as a blackhole in the meantime, so no traffic leaks outside the VPN while waiting. It tries up to 6 times, then reports an error. Controlled by Settings -> Auto reconnect (on by default); turning it off restores the old behaviour (error and stop).
- Log lines: `Airplane mode: ON/OFF`, `Network: lost`, `Network: back online`, `Reconnect: attempt n/6`, `Reconnect: connected again` (red for lost/failed, green for back online/connected).
- **Telegram:** *Join our Telegram* card on Home, a menu entry and a Help entry, opening https://t.me/hometechnol.

## Version 2.9.1

- **Public IP on the dashboard.** Connected: the exit IP is read through the tunnel (local SOCKS5 forwarder, HTTPS) and shown as *Public IP (VPN)*; the log prints `Public IP: x.x.x.x` and, after a reconnect, whether it changed. Disconnected: the tile shows *Your IP* (the phone's own address). Tap the tile to refresh.

## Version 2.9.2

- **Log header like HTTP Custom.** When the app opens the log starts with `JUAN VPN v...`, `running on <maker> (<model>)`, `Android <ver> API-<sdk> (<abi>)`, the network line (`Airtel (KE) / LTE (4G)`, `Wi-Fi`, ...) and `Local IP 10.x.x.x`. The network and Local IP lines are written again on every connect and after the network returns (airplane mode off), so you can see the local IP change. IPs in the log are green and underlined.
- The network type (LTE / 4G, 5G, 3G) needs the Phone permission (READ_PHONE_STATE). It is asked once; if you deny it the line says `Mobile data` instead.

## Hybrid TLS for SNI / borrowed domains (v2.9.4)

With a front/bug domain as SNI (for example `myaccount.telkom.co.ke` in front of your own server) the server's certificate can never match that name, so strict checking made every attempt fail with "Certificate does not match server name". The proxy layer now tries, per attempt:

1. strict check against the SNI,
2. strict check against the real SSH server name,
3. continue without a certificate check. The SSH host key (trust prompt / pinned fingerprint) then identifies the server.

Step 3 is only used when the SNI is a different name from the server's own. If the SNI is the server's own name, a bad certificate still fails. The profile is never changed; the log shows which step was used.
