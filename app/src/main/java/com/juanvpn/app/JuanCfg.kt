package com.juanvpn.app

import org.json.JSONObject

/** Profile pushed from the HTML UI. Secrets live in memory only. */
data class JuanCfg(
    val name: String, val from: String, val custom: Boolean,
    val sshHost: String, val sshPort: Int, val user: String, val pass: String, val key: String, val keyPass: String,
    val known: String, val keepalive: Int,
    val pHost: String, val pPort: Int, val pUser: String, val pPass: String, val sni: String,
    val payload: String, val wsPath: String,
    val appMode: String, val apps: List<String>
) {
    fun validate(): String? = when {
        sshHost.isBlank() -> "SSH host is required"
        sshPort !in 1..65535 -> "SSH port must be 1-65535"
        user.isBlank() -> "SSH username is required"
        pass.isEmpty() && key.isBlank() -> "Enter an SSH password or private key"
        from in listOf("http", "socks5", "tls", "ws") && pHost.isBlank() -> "Proxy host is required"
        from in listOf("http", "socks5", "tls", "ws") && pHost.isNotBlank() && pPort !in 1..65535 -> "Proxy port must be 1-65535"
        from == "tls" && sni.isBlank() -> "SNI is required for a TLS proxy"
        else -> null
    }

    companion object {
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
                s("appMode").ifBlank { "off" }, (0 until (arr?.length() ?: 0)).map { arr!!.getString(it) }
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
