package com.juanvpn.app

import org.json.JSONObject

class ProxyEntry(val host: String, val port: Int, val user: String, val pass: String)

/** Profile pushed from the HTML UI. Secrets live in memory only. */
data class JuanCfg(
    val name: String, val from: String, val custom: Boolean,
    val sshHost: String, val sshPort: Int, val user: String, val pass: String, val key: String, val keyPass: String,
    val known: String, val keepalive: Int,
    val pHost: String, val pPort: Int, val pUser: String, val pPass: String, val sni: String,
    val payload: String, val wsPath: String,
    val appMode: String, val apps: List<String>,
    val verify: Boolean = true,
    val reconnect: Boolean = true, val delay: Int = 5, val retries: Int = 5,
    val tunnel: String = "ssh",
    val xProto: String = "vless", val xHost: String = "", val xPort: Int = 443, val xSecret: String = "",
    val xMethod: String = "aes-256-gcm", val xNet: String = "tcp", val xTls: Boolean = true,
    val xSni: String = "", val xWsPath: String = "/", val xWsHost: String = "",
    val policy: JSONObject? = null,
    val proxies: List<ProxyEntry> = emptyList(),   // rotating remote proxies / fronts
    val snis: List<String> = emptyList(),          // rotating SNI names
    val payloads: List<String> = emptyList(),      // rotating payloads (separated by a line of ---)
    val pinVariant: Int = -1,                      // >= 0: smart rotation locked this copy to one combination (set by JuanRotation.pin)
    val hyHost: String = "", val hyPort: String = "443", val hyAuth: String = "", val hyUser: String = "", val hySni: String = "",
    val hyInsecure: Boolean = false, val hyObfs: String = "", val hyUp: Int = 0, val hyDown: Int = 0,
    val dnsDomain: String = "", val dnsKey: String = "", val dnsMode: String = "udp", val dnsResolver: String = "",
    val udpgw: Boolean = true, val udpgwPort: Int = 7300,
    val links: Int = 3                              // parallel SSH links for speed (1 = off)
) {
    /** Smart profile: the SSH side and the V2Ray / Shadowsocks side, each only when it is filled in correctly. */
    fun sshVariant(): JuanCfg? = copy(tunnel = "ssh").takeIf { it.validateSsh() == null }
    fun hyVariant(): JuanCfg? = copy(tunnel = "hy").takeIf { it.validateHy() == null }
    fun xVariant(): JuanCfg? = copy(tunnel = if (xProto == "ss") "ss" else "v2").takeIf { it.validateX() == null }

    fun validate(): String? = when (tunnel) {
        "smart" -> if (sshVariant() == null && xVariant() == null && hyVariant() == null) "Add an SSH, V2Ray / Shadowsocks or Hysteria server" else null
        "ssh" -> validateSsh()
        "hy" -> validateHy()
        "dnstt" -> validateDns() ?: copy(tunnel = "ssh", from = "direct", sshHost = "127.0.0.1").validateSsh()
        "dnsv2" -> validateDns() ?: copy(tunnel = if (xProto == "ss") "ss" else "v2", xHost = xHost.ifBlank { "localhost" }).validateX()
        else -> validateX()
    }

    private fun validateHy(): String? = when {
        hyHost.isBlank() -> "Hysteria server address is required"
        !Regex("\\d{1,5}(-\\d{1,5})?(,\\d{1,5}(-\\d{1,5})?)*").matches(hyPort) -> "Hysteria port must be a number or a range like 20000-30000"
        hyAuth.isEmpty() -> "Hysteria password is required"
        else -> null
    }

    private fun validateDns(): String? = when {
        dnsDomain.isBlank() -> "Name server domain is required"
        !Regex("[0-9a-fA-F]{64}").matches(dnsKey) -> "The DNSTT public key must be 64 hex characters"
        else -> null
    }

    private fun validateSsh(): String? = when {
        sshHost.isBlank() -> "SSH host is required"
        sshPort !in 1..65535 -> "SSH port must be 1-65535"
        user.isBlank() -> "SSH username is required"
        pass.isEmpty() && key.isBlank() -> "Enter an SSH password or private key"
        from in listOf("http", "socks5", "socks4", "tls", "ws") && pHost.isBlank() -> "Proxy host is required"
        from in listOf("http", "socks5", "socks4", "tls", "ws") && pHost.isNotBlank() && pPort !in 1..65535 -> "Proxy port must be 1-65535"
        (from == "sni" || from == "dpay") && pHost.isNotBlank() && pPort !in 1..65535 -> "Front port must be 1-65535"
        from == "dpay" && payload.isBlank() -> "Payload is required for Direct + Payload"
        (from == "tls" || from == "sni") && sni.isBlank() -> "SNI is required for TLS"
        else -> null
    }

    private fun validateX(): String? = when {
        xHost.isBlank() -> "Server address is required"
        xPort !in 1..65535 -> "Server port must be 1-65535"
        xSecret.isBlank() -> if (xProto == "vless" || xProto == "vmess") "UUID is required" else "Password is required"
        (xProto == "vless" || xProto == "vmess") && !Regex("[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}").matches(xSecret.trim()) -> "UUID is not valid"
        xProto == "ss" && xMethod !in SS_METHODS -> "Unsupported Shadowsocks cipher: $xMethod"
        xProto == "trojan" && !xTls -> "Trojan requires TLS"
        else -> null
    }

    companion object {
        val SS_METHODS = listOf("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305")

        fun parse(json: String): JuanCfg {
            val o = JSONObject(json)
            fun s(k: String) = o.optString(k, "")
            fun i(k: String, d: Int) = s(k).toIntOrNull() ?: d
            val arr = o.optJSONArray("apps")
            // The proxy field takes one or many entries (comma, space, semicolon or new line separated), each as
            // host, host:port, http://user:pass@host:port or [ipv6]:port. They rotate.
            val defPort = i("pPort", 443)
            fun entry(raw: String): ProxyEntry? {
                var h = raw.trim().substringAfter("://").substringBefore('/')
                if (h.isEmpty()) return null
                var port = defPort; var u = s("pUser"); var pw = s("pPass")
                if (h.contains('@')) {
                    val cred = h.substringBeforeLast('@'); h = h.substringAfterLast('@')
                    u = cred.substringBefore(':'); pw = cred.substringAfter(':', "")
                }
                if (h.startsWith("[") && h.contains(']')) {
                    val end = h.indexOf(']')
                    h.substring(end + 1).removePrefix(":").toIntOrNull()?.let { port = it }
                    h = h.substring(1, end)
                } else if (h.count { it == ':' } == 1) {
                    h.substringAfter(':').toIntOrNull()?.let { port = it }
                    h = h.substringBefore(':')
                }
                return if (h.isEmpty()) null else ProxyEntry(h, port, u, pw)
            }
            val listSep = Regex("[,;\\s]+")
            val proxies = s("pHost").split(listSep).mapNotNull { entry(it) }
            val snis = s("sni").split(listSep).map { it.trim() }.filter { it.isNotEmpty() }
            val payloads = s("payload").split(Regex("(?m)^[ \\t]*-{3,}[ \\t]*\\r?$")).filter { it.isNotBlank() }.map { it.trim('\r', '\n') }
            val ph = proxies.firstOrNull()?.host ?: ""
            val pp = proxies.firstOrNull()?.port ?: defPort
            val pu = proxies.firstOrNull()?.user ?: s("pUser")
            val ppw = proxies.firstOrNull()?.pass ?: s("pPass")
            return JuanCfg(
                s("name").ifBlank { "My server" }, s("from").ifBlank { "direct" }, o.optBoolean("custom", false),
                s("sshHost").trim(), i("sshPort", 22), s("user").trim(), s("pass"), s("key"), s("keyPass"),
                s("known"), i("keepalive", 30).coerceIn(5, 300),
                ph, pp, pu, ppw, snis.firstOrNull() ?: "",
                s("payload"), s("wsPath"),
                s("appMode").ifBlank { "off" }, (0 until (arr?.length() ?: 0)).map { arr!!.getString(it) },
                o.optBoolean("verify", true),
                o.optBoolean("reconnect", true), i("delay", 5).coerceIn(1, 60), i("retries", 5).coerceIn(1, 10),
                when (s("tunnel")) { "v2", "ss", "hy", "smart", "dnstt", "dnsv2" -> s("tunnel"); else -> "ssh" },
                when (s("tunnel")) { "ss" -> "ss"; "v2" -> s("xProto").let { if (it == "trojan" || it == "vmess") it else "vless" }; "smart", "dnsv2" -> s("xProto").let { if (it == "trojan" || it == "vmess" || it == "ss") it else "vless" }; else -> "vless" },
                s("xHost").trim(), i("xPort", 443), s("xSecret").trim(),
                s("xMethod").ifBlank { "aes-256-gcm" }.lowercase(),
                if (s("xNet") == "ws") "ws" else "tcp",
                o.optBoolean("xTls", true), s("xSni").trim(), s("xWsPath").ifBlank { "/" }, s("xWsHost").trim(),
                o.optJSONObject("_policy"),
                proxies, snis, payloads,
                hyHost = s("hyHost").trim(), hyPort = s("hyPort").trim().ifBlank { "443" }, hyAuth = s("hyAuth"), hyUser = s("hyUser").trim(), hySni = s("hySni").trim(),
                hyInsecure = o.optBoolean("hyInsecure", false), hyObfs = s("hyObfs"), hyUp = i("hyUp", 0).coerceIn(0, 100000), hyDown = i("hyDown", 0).coerceIn(0, 100000),
                dnsDomain = s("dnsDomain").trim().trimEnd('.'), dnsKey = s("dnsKey").trim(),
                dnsMode = s("dnsMode").let { if (it == "doh" || it == "dot") it else "udp" }, dnsResolver = s("dnsResolver").trim(),
                udpgw = o.optBoolean("udpgw", true), udpgwPort = i("udpgwPort", 7300).coerceIn(1, 65535),
                links = i("links", 3).coerceIn(1, 4)
            )
        }
    }
}

/** Host-key helpers: turns pasted records into lines JSch will actually match. */
object HostKeys {
    private val ws = Regex("\\s+")
    private fun isKeyType(t: String) = t.startsWith("ssh-") || t.startsWith("ecdsa-") || t.startsWith("sk-")

    fun normalize(host: String, port: Int, raw: String): String {
        val label = if (port == 22) host else "[$host]:$port"
        val out = ArrayList<String>()
        raw.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.forEach { line ->
            val p = line.split(ws)
            when {
                isKeyType(p[0]) -> out.add("$label $line")              // bare key pasted without host
                p[0] == host && port != 22 -> { out.add(line); out.add("$label ${p.drop(1).joinToString(" ")}") }
                else -> out.add(line)
            }
        }
        return out.joinToString("\n")
    }

    fun types(normalized: String): List<String> =
        normalized.lines().mapNotNull { val p = it.trim().split(ws); if (p.size >= 3 && isKeyType(p[1])) p[1] else null }.distinct()

    /** Algorithms to offer so the server presents a key type we hold a record for. */
    fun algorithms(types: List<String>): String = types.flatMap {
        if (it == "ssh-rsa") listOf("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa") else listOf(it)
    }.joinToString(",")
}
