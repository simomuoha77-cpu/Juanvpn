package com.juanvpn.app

import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/** HTTP ping through the tunnel (local SOCKS5 forwarder). Returns the HTTP status and the round trip in ms. */
object JuanPing {
    const val DEFAULT_URL = "clients3.google.com/generate_204"

    fun viaSocks(port: Int, rawUrl: String): Pair<Int, Int> {
        val raw = rawUrl.trim().ifEmpty { DEFAULT_URL }
        val url = URL(if (raw.contains("://")) raw else "http://$raw")
        val tls = url.protocol == "https"
        val host = url.host
        val p = if (url.port > 0) url.port else if (tls) 443 else 80
        val path = url.file.ifEmpty { "/" }
        val t0 = System.nanoTime()
        Socket().use { s ->
            s.connect(InetSocketAddress("127.0.0.1", port), 4000)
            s.soTimeout = 8000
            val o = s.getOutputStream(); val i = s.getInputStream()
            o.write(byteArrayOf(5, 1, 0)); o.flush()
            readFully(i, ByteArray(2))
            val hb = host.toByteArray()
            o.write(byteArrayOf(5, 1, 0, 3, hb.size.toByte()) + hb + byteArrayOf((p shr 8).toByte(), p.toByte())); o.flush()
            val r = ByteArray(4); readFully(i, r)
            if (r[1].toInt() != 0) throw java.io.IOException("connect failed")
            readFully(i, ByteArray(when (r[3].toInt()) { 1 -> 6; 4 -> 18; else -> i.read() + 2 }))
            val sock: Socket = if (tls) tlsWrap(s, host, p, true).also { it.soTimeout = 8000 } else s
            sock.getOutputStream().apply {
                write("GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".toByteArray()); flush()
            }
            val line = StringBuilder()
            val ins = sock.getInputStream()
            while (line.length < 64) { val c = ins.read(); if (c < 0 || c == 10) break; line.append(c.toChar()) }
            val code = line.toString().trim().split(" ").getOrNull(1)?.toIntOrNull() ?: throw java.io.IOException("bad reply")
            return Pair(code, ((System.nanoTime() - t0) / 1_000_000).toInt())
        }
    }

    private fun readFully(i: java.io.InputStream, b: ByteArray) {
        var n = 0
        while (n < b.size) { val r = i.read(b, n, b.size - n); if (r < 0) throw java.io.IOException("closed"); n += r }
    }
}
