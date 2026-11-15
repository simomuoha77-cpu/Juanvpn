package com.juanvpn.app

import org.json.JSONObject

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
    val policy: JSONObject? = null
) {
    fun validate(): String? = if (tunnel != "ssh") validateX() else when {
        sshHost.isBlank() -> "SSH host is required"
        sshPort !in 1..65535 -> "SSH port must be 1-65535"
        user.isBlank() -> "SSH username is required"
        pass.isEmpty() && key.isBlank() -> "Enter an SSH password or private key"
        from in listOf("http", "socks5", "tls", "ws") && pHost.isBlank() -> "Proxy host is required"
        from in listOf("http", "socks5", "tls", "ws") && pHost.isNotBlank() && pPort !in 1..65535 -> "Proxy port must be 1-65535"
        from == "sni" && pHost.isNotBlank() && pPort !in 1..65535 -> "Front port must be 1-65535"
        (from == "tls" || from == "sni") && sni.isBlank() -> "SNI is required for TLS"
        else -> null
    }

    private fun validateX(): String? = when {
        tunnel == "hy" -> "Hysteria needs a QUIC engine that is not bundled in this build"
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
            return JuanCfg(
                s("name").ifBlank { "My server" }, s("from").ifBlank { "direct" }, o.optBoolean("custom", false),
                s("sshHost").trim(), i("sshPort", 22), s("user").trim(), s("pass"), s("key"), s("keyPass"),
                s("known"), i("keepalive", 30).coerceIn(5, 300),
                s("pHost").trim(), i("pPort", 443), s("pUser"), s("pPass"), s("sni").trim(),
                s("payload"), s("wsPath"),
                s("appMode").ifBlank { "off" }, (0 until (arr?.length() ?: 0)).map { arr!!.getString(it) },
                o.optBoolean("verify", true),
                o.optBoolean("reconnect", true), i("delay", 5).coerceIn(1, 60), i("retries", 5).coerceIn(1, 10),
                when (s("tunnel")) { "v2", "ss", "hy" -> s("tunnel"); else -> "ssh" },
                when (s("tunnel")) { "ss" -> "ss"; "v2" -> s("xProto").let { if (it == "trojan" || it == "vmess") it else "vless" }; else -> "vless" },
                s("xHost").trim(), i("xPort", 443), s("xSecret").trim(),
                s("xMethod").ifBlank { "aes-256-gcm" }.lowercase(),
                if (s("xNet") == "ws") "ws" else "tcp",
                o.optBoolean("xTls", true), s("xSni").trim(), s("xWsPath").ifBlank { "/" }, s("xWsHost").trim(),
                o.optJSONObject("_policy")
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
