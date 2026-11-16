package com.juanvpn.app

import android.util.Base64
import com.jcraft.jsch.Proxy
import com.jcraft.jsch.SocketFactory
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.util.concurrent.atomic.AtomicInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

private val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
    override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
    override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
})

/** TLS with SNI. By default the certificate chain and hostname are verified; verify=false is an explicit user choice. */
fun tlsWrap(plain: Socket, sni: String, port: Int, verify: Boolean = true): SSLSocket {
    val factory = if (verify) SSLSocketFactory.getDefault() as SSLSocketFactory
    else javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, trustAll, java.security.SecureRandom()) }.socketFactory
    val s = factory.createSocket(plain, sni, port, true) as SSLSocket
    s.enabledProtocols = s.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
    // Make sure the SNI we want is what is sent, even when it is not a plain hostname.
    try {
        val p = s.sslParameters
        if (!sni.matches(Regex("[0-9.:]+"))) p.serverNames = listOf(javax.net.ssl.SNIHostName(sni))
        s.sslParameters = p
    } catch (_: Throwable) {}
    s.startHandshake()
    if (verify && !HttpsURLConnection.getDefaultHostnameVerifier().verify(sni, s.session))
        throw SSLPeerUnverifiedException("Certificate does not match server name '$sni'")
    return s
}

private val IPV4 = Regex("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})")

/**
 * Payload engine. Understands the placeholders used by the common injector apps:
 *  [host] [port] [host_port] [ssh] [ssh_host] [ssh_port] [protocol] [method] [netData] [raw] [realData]
 *  [crlf] [cr] [lf] [lfcr] [tab] [ua] [sni] [proxy] [proxy_port] [path] [auth]
 *  [rotate=a;b;c] [random=a;b;c]  [split] [instant_split] [delay_split] [delay=ms]
 * Everything after a blank line is sent too, so multi-request payloads (decoy request + upgrade) work.
 */
object JuanPayload {
    const val UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    private val rnd = java.util.Random()
    private val tag = Regex("\\[([A-Za-z_]+)(?:=([^\\]]*))?\\]")
    private val marker = Regex("\u0001([SID]|T\\d+)\\u0001")
    private val reqLine = Regex("(?:^|\\n)[A-Za-z]+ \\S+ HTTP/\\d(?:\\.\\d)?\\r?\\n")

    class Part(val data: ByteArray, val pauseMs: Long)

    private class Choice(val start: Int, val end: Int, val random: Boolean, val options: List<String>)
    private val choiceOpen = Regex("\\[(rotate|random)=", RegexOption.IGNORE_CASE)
    private val randomOffset = rnd.nextInt(1000)

    /** Finds every [rotate=a;b] / [random=a;b]. Bracket-aware, so options may contain tags like [crlf]. */
    private fun choices(t: String): List<Choice> {
        val out = ArrayList<Choice>()
        var from = 0
        while (true) {
            val m = choiceOpen.find(t, from) ?: break
            var depth = 1
            var i = m.range.last + 1
            while (i < t.length && depth > 0) { if (t[i] == '[') depth++ else if (t[i] == ']') depth--; i++ }
            if (depth != 0) break
            val arg = t.substring(m.range.last + 1, i - 1)
            out.add(Choice(m.range.first, i, m.groupValues[1].equals("random", true), arg.split(';').filter { it.isNotEmpty() }))
            from = i
        }
        return out
    }

    /** How many different payloads a rotate/random tag can produce (1 when there is none). */
    fun variantCount(payload: String): Int = maxOf(1, choices(payload).maxOfOrNull { it.options.size } ?: 1)

    private fun expandChoices(payload: String, rot: Int): String {
        var t = payload
        for (ch in choices(payload).reversed()) {
            val pick = if (ch.options.isEmpty()) "" else ch.options[Math.floorMod(if (ch.random) rot + randomOffset else rot, ch.options.size)]
            t = t.substring(0, ch.start) + pick + t.substring(ch.end)
        }
        return t
    }

    fun build(c: JuanCfg, payload: String, sni: String, host: String, port: Int, rot: Int): List<Part> {
        var t = expandChoices(payload, rot)
        // literal \r\n typed as text
        t = t.replace("\\r\\n", "[crlf]").replace("\\n", "[lf]").replace("\\r", "[cr]")
        val hasTags = Regex("\\[(crlf|cr|lf|lfcr)\\]", RegexOption.IGNORE_CASE).containsMatchIn(t)
        t = t.replace("\r\n", "\n").replace("\r", "\n")
        t = if (hasTags) t.replace("\n", "") else t.replace("\n", "\r\n")   // typed line breaks become CRLF when no tags are used
        val hp = "$host:$port"
        t = tag.replace(t) { m ->
            val name = m.groupValues[1].lowercase()
            val arg = m.groupValues[2]
            when (name) {
                "crlf" -> "\r\n"; "cr" -> "\r"; "lf" -> "\n"; "lfcr" -> "\n\r"; "tab" -> "\t"; "space" -> " "
                "host", "ssh_host" -> host
                "port", "ssh_port" -> port.toString()
                "host_port", "ssh" -> hp
                "protocol" -> "HTTP/1.1"
                "method" -> "CONNECT"
                "netdata", "raw", "realdata", "real_raw", "rawdata" -> "CONNECT $hp HTTP/1.1"
                "ua", "user_agent" -> UA
                "sni" -> sni.ifBlank { host }
                "proxy", "proxy_host" -> c.pHost
                "proxy_port" -> c.pPort.toString()
                "sni_rotate" -> sni.ifBlank { host }
                "path" -> c.wsPath.ifBlank { "/" }
                "auth" -> if (c.pUser.isNotEmpty()) "Proxy-Authorization: Basic " +
                    Base64.encodeToString("${c.pUser}:${c.pPass}".toByteArray(), Base64.NO_WRAP) else ""
                "rotate" -> arg.split(';').filter { it.isNotEmpty() }.let { if (it.isEmpty()) "" else it[Math.floorMod(rot, it.size)] }
                "random" -> arg.split(';').filter { it.isNotEmpty() }.let { if (it.isEmpty()) "" else it[rnd.nextInt(it.size)] }
                "split" -> "\u0001S\u0001"
                "instant_split" -> "\u0001I\u0001"
                "delay_split", "split_delay" -> "\u0001D\u0001"
                "delay" -> "\u0001T" + (arg.toLongOrNull() ?: 1000L).coerceIn(0L, 10_000L) + "\u0001"
                else -> m.value
            }
        }
        val parts = ArrayList<Part>()
        var last = 0
        fun add(seg: String, pause: Long) {
            if (seg.isNotEmpty()) parts.add(Part(bytes(seg), pause))
            else if (parts.isNotEmpty() && pause > 0) { val p = parts.removeAt(parts.size - 1); parts.add(Part(p.data, p.pauseMs + pause)) }
        }
        for (m in marker.findAll(t)) {
            val k = m.groupValues[1]
            val pause = when (k) { "S" -> 200L; "I" -> 0L; "D" -> 1500L; else -> k.drop(1).toLong() }
            add(t.substring(last, m.range.first), pause)
            last = m.range.last + 1
        }
        var tail = t.substring(last)
        // An HTTP request that forgot its closing blank line would hang forever: finish it.
        if (tail.contains(" HTTP/") && !tail.endsWith("\r\n\r\n") && !tail.endsWith("\n\n"))
            tail += if (tail.endsWith("\r\n")) "\r\n" else "\r\n\r\n"
        add(tail, 0)
        return parts
    }

    private fun bytes(s: String) = if (s.any { it.code > 255 }) s.toByteArray(Charsets.UTF_8) else s.toByteArray(Charsets.ISO_8859_1)

    /** How many HTTP replies to expect (one per request line in the payload). 0 = not HTTP, do not wait. */
    fun expectedReplies(parts: List<Part>): Int {
        val all = parts.joinToString("") { String(it.data, Charsets.ISO_8859_1) }
        return reqLine.findAll("\n" + all).count()
    }
}

/** Real upstream transport for SSH: direct, HTTP CONNECT/payload, SOCKS4/5, TLS(+SNI)+payload, WebSocket upgrade, direct payload. */
class JuanProxy(private val c: JuanCfg, private val log: (String) -> Unit, private val protect: (Socket) -> Unit = {}) : Proxy {
    private var sock: Socket? = null
    private var ins: InputStream? = null
    private var outs: OutputStream? = null

    private companion object { val rotation = AtomicInteger() }

    /**
     * Rotation: every connection starts at the next proxy / SNI / payload in the lists and, when one is
     * rejected, falls through to the next combination (up to 12 tries) before giving up.
     */
    override fun connect(sf: SocketFactory?, host: String, port: Int, timeout: Int) {
        val pxs: List<ProxyEntry?> = if (c.from == "direct" || c.proxies.isEmpty()) listOf(null) else c.proxies
        val snis = c.snis.ifEmpty { listOf(c.sni) }
        val pays = c.payloads.ifEmpty { listOf(c.payload) }
        // every option of a [rotate=..]/[random=..] tag is its own candidate payload
        val cands = ArrayList<Pair<String, Int>>()
        for (p in pays) for (v in 0 until JuanPayload.variantCount(p)) cands.add(p to v)
        val total = pxs.size * snis.size * cands.size
        val start = rotation.getAndIncrement()
        val tries = minOf(total, 12)
        val to = if (tries > 1) minOf(timeout, 10_000) else timeout
        var last: Exception? = null
        for (n in 0 until tries) {
            val idx = Math.floorMod(start + n, total)
            val pi = idx % cands.size
            val si = (idx / cands.size) % snis.size
            val xi = idx / (cands.size * snis.size)
            if (total > 1) log("Rotation: try ${n + 1}/$tries" + (if (pxs.size > 1) ", proxy ${xi + 1}/${pxs.size}" else "") +
                (if (snis.size > 1) ", SNI ${snis[si]}" else "") + (if (cands.size > 1) ", payload ${pi + 1}/${cands.size}" else ""))
            try { attempt(host, port, to, pxs[xi], snis[si], cands[pi].first, cands[pi].second); return }
            catch (e: InterruptedException) { throw e }
            catch (e: Exception) {
                last = e
                if (tries == 1) throw e
                log("Rotation: failed (${e.message?.take(120)}), trying the next one")
            }
        }
        rotation.addAndGet(tries - 1)        // next connect continues after the ones already tried
        throw last ?: IOException("No connection candidate")
    }

    private fun attempt(host: String, port: Int, timeout: Int, px: ProxyEntry?, sniName: String, payload: String, rot: Int) {
        val viaProxy = c.from != "direct" && px != null
        val th = if (viaProxy) px!!.host else host
        val tp = if (viaProxy) px!!.port else port
        val pUser = px?.user ?: c.pUser
        val pPass = px?.pass ?: c.pPass
        log("DNS: resolving $th")
        val addr = InetAddress.getByName(th)
        log("DNS: $th -> ${addr.hostAddress}")
        var s = Socket()
        protect(s)
        try {
            s.connect(InetSocketAddress(addr, tp), timeout)
            s.soTimeout = timeout
            s.tcpNoDelay = true
            log("Proxy: TCP connected ${addr.hostAddress}:$tp (${c.from})")
            if (c.from == "tls" || c.from == "sni" || (c.from == "ws" && sniName.isNotBlank())) {
                val name = sniName.ifBlank { th }
                if (name.matches(Regex("[0-9.:]+"))) log("TLS: warning - SNI is an IP address; servers usually need a domain name here")
                log("TLS: handshake, SNI=$name")
                if (!c.verify) log("TLS: warning - certificate verification is OFF")
                val ssl = tlsWrap(s, name, tp, c.verify)
                log("TLS: ${ssl.session.protocol} ${ssl.session.cipherSuite}" + if (c.verify) ", certificate verified" else "")
                s = ssl
            }
            val i = PushbackInputStream(s.getInputStream(), 32)
            val o = s.getOutputStream()
            val custom = payload.isNotBlank() && (c.custom || c.from == "dpay")
            when (c.from) {
                "http" -> {
                    if (custom) sendPayload(o, i, payload, sniName, host, port, rot)
                    else {
                        val auth = if (pUser.isNotEmpty()) "Proxy-Authorization: Basic " +
                            Base64.encodeToString("$pUser:$pPass".toByteArray(), Base64.NO_WRAP) + "\r\n" else ""
                        o.write("CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\nProxy-Connection: keep-alive\r\n$auth\r\n".toByteArray(Charsets.ISO_8859_1)); o.flush()
                        awaitTunnel(i, 1)
                    }
                }
                "socks5" -> socks5(i, o, host, port, pUser, pPass)
                "socks4" -> socks4(i, o, host, port, pUser)
                "tls", "sni", "dpay" -> if (custom) sendPayload(o, i, payload, sniName, host, port, rot)
                "ws" -> {
                    if (custom) sendPayload(o, i, payload, sniName, host, port, rot)
                    else {
                        val key = Base64.encodeToString(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }, Base64.NO_WRAP)
                        o.write(("GET ${c.wsPath.ifBlank { "/" }} HTTP/1.1\r\nHost: ${sniName.ifBlank { host }}\r\nUpgrade: websocket\r\n" +
                            "Connection: Upgrade\r\nSec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n\r\n").toByteArray(Charsets.ISO_8859_1)); o.flush()
                        awaitTunnel(i, 1)
                    }
                }
            }
            s.soTimeout = 0
            sock = s; ins = i; outs = o
        } catch (e: Exception) {
            try { s.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun sendPayload(o: OutputStream, i: PushbackInputStream, payload: String, sni: String, host: String, port: Int, rot: Int) {
        val parts = JuanPayload.build(c, payload, sni, host, port, rot)
        if (parts.isEmpty()) throw IOException("The payload is empty after processing")
        for ((n, p) in parts.withIndex()) {
            o.write(p.data); o.flush()
            if (p.pauseMs > 0 && n < parts.size - 1) Thread.sleep(p.pauseMs)
        }
        val text = String(parts[0].data, Charsets.ISO_8859_1)
        val reqLine = text.lineSequence().firstOrNull { it.isNotBlank() }?.trim()?.take(80) ?: ""
        val hostHdr = Regex("(?im)^host:[ \\t]*(.+)$").find(text)?.groupValues?.get(1)?.trim()?.take(80)
        log("Payload: $reqLine" + (if (hostHdr != null) " | Host: $hostHdr" else ""))
        val expect = JuanPayload.expectedReplies(parts)
        log("Payload: sent ${parts.sumOf { it.data.size }} bytes in ${parts.size} part(s), $expect HTTP request(s)")
        if (expect == 0) { log("Payload: not an HTTP request, not waiting for a reply"); return }
        awaitTunnel(i, expect)
    }

    /**
     * Reads replies until the tunnel is open. Replies to earlier (decoy) requests are skipped; 101 or a 2xx to
     * the last request opens the tunnel; an SSH banner arriving first also means the tunnel is already open.
     */
    private fun awaitTunnel(i: PushbackInputStream, expected: Int) {
        var left = expected
        var saw2xx = false
        while (true) {
            val head = try { readHead(i) } catch (e: java.net.SocketTimeoutException) {
                if (saw2xx) { log("Proxy: no further reply, continuing"); return }
                throw e
            }
            if (head == null) { log("Proxy: SSH banner received, tunnel is open"); return }
            val first = head.substringBefore("\n").trim()
            val code = first.split(" ").getOrNull(1)?.toIntOrNull()
            left--
            when {
                code == 101 -> { log("Proxy: handshake OK ($first)"); return }
                code != null && code in 200..299 && left <= 0 -> { log("Proxy: handshake OK ($first)"); return }
                code != null && code in 200..299 -> { saw2xx = true; log("Proxy: skipping reply to earlier request ($first)"); skipBody(i, head) }
                left > 0 -> { log("Proxy: skipping reply to earlier request ($first)"); skipBody(i, head) }
                else -> throw IOException("Proxy replied: $first")
            }
        }
    }

    /** Returns the reply head, or null when the server started with an SSH banner (bytes are pushed back). */
    private fun readHead(i: PushbackInputStream): String? {
        val sb = StringBuilder()
        while (sb.length < 16384) {
            val b = i.read()
            if (b < 0) throw IOException("Proxy closed the connection during handshake")
            if (sb.isEmpty() && (b == 13 || b == 10)) continue            // stray blank lines before a reply
            sb.append(b.toChar())
            if (sb.length == 4 && sb.toString() == "SSH-") { i.unread("SSH-".toByteArray()); return null }
            if (sb.length == 5 && !sb.startsWith("HTTP/")) throw IOException("Unexpected reply from the proxy (not HTTP): " + sb.toString().filter { it.code in 32..126 })
            if (sb.endsWith("\r\n\r\n") || sb.endsWith("\n\n")) return sb.toString()
        }
        throw IOException("Proxy response too large")
    }

    private fun skipBody(i: InputStream, head: String) {
        val h = head.lowercase()
        val len = Regex("content-length:\\s*(\\d+)").find(h)?.groupValues?.get(1)?.toLongOrNull()
        when {
            len != null && len > 0 -> { var left = minOf(len, 2_000_000L); val buf = ByteArray(4096); while (left > 0) { val n = i.read(buf, 0, minOf(left, buf.size.toLong()).toInt()); if (n < 0) break; left -= n } }
            h.contains("transfer-encoding: chunked") -> {
                while (true) {
                    val line = readLine(i)
                    val size = line.substringBefore(";").trim().toIntOrNull(16) ?: break
                    if (size == 0) { while (readLine(i).isNotEmpty()) { }; break }
                    var left = size + 2
                    val buf = ByteArray(4096)
                    while (left > 0) { val n = i.read(buf, 0, minOf(left, buf.size)); if (n < 0) return; left -= n }
                }
            }
        }
    }

    private fun readLine(i: InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 1024) { val b = i.read(); if (b < 0 || b == 10) break; if (b != 13) sb.append(b.toChar()) }
        return sb.toString()
    }

    private fun socks5(i: InputStream, o: OutputStream, host: String, port: Int, pUser: String, pPass: String) {
        val auth = pUser.isNotEmpty()
        o.write(if (auth) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0)); o.flush()
        val m = ByteArray(2).also { readFully(i, it) }
        if (m[0].toInt() != 5 || (m[1].toInt() and 0xFF) == 0xFF) throw IOException("SOCKS5 proxy rejected authentication methods")
        if (m[1].toInt() == 2) {
            val u = pUser.toByteArray(); val p = pPass.toByteArray()
            o.write(byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p); o.flush()
            val r = ByteArray(2).also { readFully(i, it) }
            if (r[1].toInt() != 0) throw IOException("SOCKS5 proxy credentials rejected")
        }
        val dest: ByteArray = when {
            IPV4.matches(host) -> byteArrayOf(1) + InetAddress.getByName(host).address
            host.contains(':') -> byteArrayOf(4) + InetAddress.getByName(host).address
            else -> { val h = host.toByteArray(); byteArrayOf(3, h.size.toByte()) + h }
        }
        o.write(byteArrayOf(5, 1, 0) + dest + byteArrayOf((port shr 8).toByte(), port.toByte())); o.flush()
        val r = ByteArray(4).also { readFully(i, it) }
        if (r[1].toInt() != 0) throw IOException("SOCKS5 connect failed (code ${r[1]})")
        val skip = when (r[3].toInt()) { 1 -> 6; 4 -> 18; else -> i.read() + 2 }
        readFully(i, ByteArray(skip))
        log("Proxy: SOCKS5 CONNECT OK")
    }

    /** SOCKS4, and SOCKS4a for host names. */
    private fun socks4(i: InputStream, o: OutputStream, host: String, port: Int, pUser: String) {
        val v4 = IPV4.matches(host)
        val b = java.io.ByteArrayOutputStream()
        b.write(4); b.write(1); b.write(port shr 8); b.write(port and 0xFF)
        if (v4) b.write(InetAddress.getByName(host).address) else b.write(byteArrayOf(0, 0, 0, 1))
        b.write(pUser.toByteArray()); b.write(0)
        if (!v4) { b.write(host.toByteArray()); b.write(0) }
        o.write(b.toByteArray()); o.flush()
        val r = ByteArray(8).also { readFully(i, it) }
        if ((r[1].toInt() and 0xFF) != 0x5A) throw IOException("SOCKS4 connect failed (code ${r[1].toInt() and 0xFF})")
        log("Proxy: SOCKS4 CONNECT OK")
    }

    private fun readFully(i: InputStream, b: ByteArray) {
        var n = 0
        while (n < b.size) { val r = i.read(b, n, b.size - n); if (r < 0) throw IOException("Proxy closed the connection"); n += r }
    }

    override fun getInputStream(): InputStream = ins!!
    override fun getOutputStream(): OutputStream = outs!!
    override fun getSocket(): Socket? = sock
    override fun close() { try { sock?.close() } catch (_: Exception) {} }
}
