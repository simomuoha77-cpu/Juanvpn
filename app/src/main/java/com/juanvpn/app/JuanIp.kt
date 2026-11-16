package com.juanvpn.app

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/** Finds the public IP. Through the tunnel (local SOCKS5 forwarder) when connected, directly otherwise. */
object JuanIp {
    private val hosts = listOf("api.ipify.org", "icanhazip.com", "ifconfig.me")
    private val v4 = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")

    private fun pick(text: String): String? = v4.find(text)?.value

    /** Not through the VPN (the app's own traffic bypasses it), so this is the phone's own IP. */
    fun direct(): String? {
        for (h in hosts) try {
            val c = URL("https://$h/").openConnection() as HttpURLConnection
            c.connectTimeout = 6000; c.readTimeout = 6000
            c.setRequestProperty("User-Agent", "curl/8")
            val t = c.inputStream.bufferedReader().use { it.readText().take(2000) }
            pick(t)?.let { return it }
        } catch (_: Exception) {}
        return null
    }

    /** The IP the outside world sees for traffic that goes through the tunnel. */
    fun viaSocks(port: Int): String? {
        for (h in hosts) try {
            Socket().use { s ->
                s.connect(InetSocketAddress("127.0.0.1", port), 5000)
                s.soTimeout = 9000
                val o = s.getOutputStream(); val i = s.getInputStream()
                o.write(byteArrayOf(5, 1, 0)); o.flush()
                val m = ByteArray(2); readFully(i, m)
                val hb = h.toByteArray()
                o.write(byteArrayOf(5, 1, 0, 3, hb.size.toByte()) + hb + byteArrayOf(0x01, 0xBB.toByte())); o.flush()   // port 443
                val r = ByteArray(4); readFully(i, r)
                if (r[1].toInt() != 0) throw java.io.IOException("SOCKS connect failed")
                readFully(i, ByteArray(when (r[3].toInt()) { 1 -> 6; 4 -> 18; else -> i.read() + 2 }))
                val ssl = tlsWrap(s, h, 443, true)
                ssl.soTimeout = 9000
                ssl.getOutputStream().apply {
                    write("GET / HTTP/1.1\r\nHost: $h\r\nUser-Agent: curl/8\r\nAccept: */*\r\nConnection: close\r\n\r\n".toByteArray()); flush()
                }
                val sb = StringBuilder(); val buf = ByteArray(2048)
                val ins = ssl.getInputStream()
                while (sb.length < 4000) { val n = ins.read(buf); if (n < 0) break; sb.append(String(buf, 0, n, Charsets.ISO_8859_1)) }
                val body = sb.toString().substringAfter("\r\n\r\n", "")
                pick(body)?.let { return it }
            }
        } catch (_: Exception) {}
        return null
    }

    private fun readFully(i: java.io.InputStream, b: ByteArray) {
        var n = 0
        while (n < b.size) { val r = i.read(b, n, b.size - n); if (r < 0) throw java.io.IOException("closed"); n += r }
    }
}
