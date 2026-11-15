package com.juanvpn.app

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.SSLSocket

/** Real diagnostics. Each returns a plain-text explanation. */
object JuanTools {
    private fun ms(t: Long) = "${System.currentTimeMillis() - t} ms"
    private fun tcp(h: String, p: Int): Socket { val s = Socket(); s.connect(InetSocketAddress(h, p), 6000); s.soTimeout = 6000; return s }

    fun run(name: String, j: JSONObject): String {
        val host = j.optString("host"); val port = j.optString("port").toIntOrNull() ?: 22
        val proxy = j.optString("proxy"); val sni = j.optString("sni")
        fun t(f: () -> String) = try { f() } catch (e: Exception) { "FAILED: ${e.javaClass.simpleName}: ${e.message}" }
        return when (name) {
            "dns" -> t { val t0 = System.currentTimeMillis(); InetAddress.getAllByName(host).joinToString("\n", "$host resolved in ${ms(t0)}\n") { it.hostAddress ?: "" } }
            "reach" -> t { val t0 = System.currentTimeMillis(); tcp(host, port).use { "TCP $host:$port reachable (${ms(t0)})" } }
            "ssh" -> t { tcp(host, port).use { s -> val b = s.getInputStream().bufferedReader().readLine() ?: ""
                if (b.startsWith("SSH-")) "SSH server answered: $b" else "Port open but no SSH banner (got: ${b.take(60)}). A proxy or payload may be required." } }
            "proxy" -> t { val h = proxy.substringBeforeLast(":"); val p = proxy.substringAfterLast(":").toIntOrNull() ?: 443
                if (h.isBlank()) "No proxy host set" else { val t0 = System.currentTimeMillis(); tcp(h, p).use { "Proxy $h:$p reachable (${ms(t0)})" } } }
            "tls" -> t { val h = proxy.substringBeforeLast(":").ifBlank { host }; val p = proxy.substringAfterLast(":").toIntOrNull() ?: 443
                val name = sni.ifBlank { h }; val s = tlsWrap(tcp(h, p), name, p)
                s.use { x -> "TLS OK to $h:$p, SNI=$name\n${x.session.protocol} ${x.session.cipherSuite}\n" +
                    "Certificate: ${(x.session.peerCertificates[0] as java.security.cert.X509Certificate).subjectX500Principal.name}\nChain and hostname verified." } }
            "ip" -> t { val c = URL("https://api.ipify.org").openConnection() as HttpURLConnection; c.connectTimeout = 6000; c.readTimeout = 6000
                "Public IP: " + c.inputStream.bufferedReader().readText().trim() }
            "diag" -> listOf("dns", "reach", "ssh", "proxy", "tls", "ip").joinToString("\n\n") { "[$it]\n" + run(it, j) }
            else -> "Unknown test"
        }
    }
}
