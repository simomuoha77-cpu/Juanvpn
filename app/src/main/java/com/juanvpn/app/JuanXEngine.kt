package com.juanvpn.app

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Common surface used by the VPN service for every tunnel type. Each engine exposes a local SOCKS5 port. */
interface TunnelEngine {
    val up: AtomicLong
    val down: AtomicLong
    val socksPort: Int
    var probeError: String
    fun start()
    fun alive(): Boolean
    fun probe(): Boolean
    fun stop()
}

class Link(val i: InputStream, val o: OutputStream, val sock: Socket) {
    fun close() { try { sock.close() } catch (_: Exception) {} }
}

/* ---------------------------------------------------------------- WebSocket framing (client side) */

class WsCodec(private val raw: InputStream, private val rawOut: OutputStream) {
    private val rnd = SecureRandom()
    private val wl = Any()

    private fun sendFrame(op: Int, data: ByteArray, off: Int, len: Int) = synchronized(wl) {
        val h = ByteArrayOutputStream()
        h.write(0x80 or op)
        when {
            len < 126 -> h.write(0x80 or len)
            len <= 0xFFFF -> { h.write(0x80 or 126); h.write(len shr 8); h.write(len and 0xFF) }
            else -> { h.write(0x80 or 127); for (k in 7 downTo 0) h.write(((len.toLong() shr (8 * k)) and 0xFF).toInt()) }
        }
        val mask = ByteArray(4).also { rnd.nextBytes(it) }
        h.write(mask)
        val body = ByteArray(len) { (data[off + it].toInt() xor mask[it and 3].toInt()).toByte() }
        h.write(body)
        rawOut.write(h.toByteArray()); rawOut.flush()
    }

    val output: OutputStream = object : OutputStream() {
        override fun write(b: Int) { write(byteArrayOf(b.toByte()), 0, 1) }
        override fun write(b: ByteArray, off: Int, len: Int) {
            var p = 0
            while (p < len) { val n = minOf(len - p, 16384); sendFrame(2, b, off + p, n); p += n }
        }
        override fun flush() { rawOut.flush() }
        override fun close() { try { sendFrame(8, ByteArray(0), 0, 0) } catch (_: Exception) {} }
    }

    private fun readFully(b: ByteArray) {
        var n = 0
        while (n < b.size) { val r = raw.read(b, n, b.size - n); if (r < 0) throw IOException("WebSocket closed by server"); n += r }
    }

    val input: InputStream = object : InputStream() {
        private var remain = 0L
        private var closed = false

        override fun read(): Int {
            val b = ByteArray(1)
            val n = read(b, 0, 1)
            return if (n < 0) -1 else b[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (remain == 0L) {
                if (closed) return -1
                if (!frame()) return -1
            }
            val n = raw.read(b, off, minOf(len.toLong(), remain).toInt())
            if (n < 0) return -1
            remain -= n
            return n
        }

        private fun frame(): Boolean {
            val b0 = raw.read()
            if (b0 < 0) { closed = true; return false }
            val b1 = raw.read()
            if (b1 < 0) { closed = true; return false }
            val op = b0 and 0x0F
            val masked = (b1 and 0x80) != 0
            var len = (b1 and 0x7F).toLong()
            if (len == 126L) { val e = ByteArray(2); readFully(e); len = (((e[0].toInt() and 0xFF) shl 8) or (e[1].toInt() and 0xFF)).toLong() }
            else if (len == 127L) { val e = ByteArray(8); readFully(e); len = 0; for (x in e) len = (len shl 8) or (x.toLong() and 0xFF) }
            if (masked) throw IOException("WebSocket server sent a masked frame")
            when (op) {
                0, 1, 2 -> remain = len
                8 -> { closed = true; if (len > 0) readFully(ByteArray(len.toInt())); return false }
                9 -> { val p = ByteArray(len.toInt()); readFully(p); sendFrame(10, p, 0, p.size) }
                10 -> if (len > 0) readFully(ByteArray(len.toInt()))
                else -> throw IOException("WebSocket: unexpected opcode $op")
            }
            return true
        }
    }
}

/* ---------------------------------------------------------------- VLESS response header stripper */

private class VlessIn(private val i: InputStream) : InputStream() {
    private var done = false
    private fun head() {
        if (done) return
        done = true
        val v = i.read(); val l = i.read()
        if (v < 0 || l < 0) throw IOException("Server closed the connection (wrong UUID or server rejected the request)")
        var skip = l
        while (skip > 0) { if (i.read() < 0) throw IOException("Server closed the connection"); skip-- }
    }
    override fun read(): Int { head(); return i.read() }
    override fun read(b: ByteArray, off: Int, len: Int): Int { head(); return i.read(b, off, len) }
}

/* ---------------------------------------------------------------- Shadowsocks AEAD */

class SsCrypto(method: String, password: String) {
    private val chacha = method == "chacha20-ietf-poly1305"
    val keyLen = if (method == "aes-128-gcm") 16 else 32
    val saltLen = keyLen
    private val master: ByteArray

    init {
        val md = MessageDigest.getInstance("MD5")
        val pw = password.toByteArray(Charsets.UTF_8)
        var prev = ByteArray(0)
        val out = ByteArrayOutputStream()
        while (out.size() < keyLen) { md.update(prev); md.update(pw); prev = md.digest(); out.write(prev) }
        master = out.toByteArray().copyOf(keyLen)
    }

    fun subkey(salt: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(salt, "HmacSHA1"))
        val prk = mac.doFinal(master)
        mac.init(SecretKeySpec(prk, "HmacSHA1"))
        val info = "ss-subkey".toByteArray()
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var n = 1
        while (out.size() < keyLen) {
            mac.update(t); mac.update(info); mac.update(n.toByte())
            t = mac.doFinal(); out.write(t); n++
        }
        return out.toByteArray().copyOf(keyLen)
    }

    fun seal(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        if (chacha) {
            val c = ChaCha20Poly1305()
            c.init(true, AEADParameters(KeyParameter(key), 128, nonce))
            val out = ByteArray(c.getOutputSize(data.size))
            var n = c.processBytes(data, 0, data.size, out, 0)
            n += c.doFinal(out, n)
            return out.copyOf(n)
        }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return c.doFinal(data)
    }

    fun open(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        try {
            if (chacha) {
                val c = ChaCha20Poly1305()
                c.init(false, AEADParameters(KeyParameter(key), 128, nonce))
                val out = ByteArray(c.getOutputSize(data.size))
                var n = c.processBytes(data, 0, data.size, out, 0)
                n += c.doFinal(out, n)
                return out.copyOf(n)
            }
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            return c.doFinal(data)
        } catch (e: Exception) {
            throw IOException("Shadowsocks: bad data from server (wrong password or cipher)")
        }
    }
}

private fun bump(n: ByteArray) { for (k in n.indices) { n[k]++; if (n[k] != 0.toByte()) break } }

private class SsOut(private val o: OutputStream, private val cr: SsCrypto) : OutputStream() {
    private var key: ByteArray? = null
    private val nonce = ByteArray(12)
    private fun ensure(): ByteArray {
        key?.let { return it }
        val salt = ByteArray(cr.saltLen).also { SecureRandom().nextBytes(it) }
        val k = cr.subkey(salt)
        o.write(salt)
        key = k
        return k
    }
    override fun write(b: Int) { write(byteArrayOf(b.toByte()), 0, 1) }
    override fun write(b: ByteArray, off: Int, len: Int) {
        val k = ensure()
        var p = 0
        val buf = ByteArrayOutputStream()
        while (p < len) {
            val n = minOf(len - p, 0x3FFF)
            val l = cr.seal(k, nonce, byteArrayOf((n shr 8).toByte(), n.toByte())); bump(nonce)
            val d = cr.seal(k, nonce, b.copyOfRange(off + p, off + p + n)); bump(nonce)
            buf.write(l); buf.write(d)
            p += n
        }
        o.write(buf.toByteArray())
    }
    override fun flush() { o.flush() }
}

private class SsIn(private val i: InputStream, private val cr: SsCrypto) : InputStream() {
    private var key: ByteArray? = null
    private val nonce = ByteArray(12)
    private var buf = ByteArray(0)
    private var pos = 0

    private fun fully(b: ByteArray): Boolean {
        var n = 0
        while (n < b.size) { val r = i.read(b, n, b.size - n); if (r < 0) { if (n == 0) return false; throw IOException("Shadowsocks: connection cut mid-chunk") }; n += r }
        return true
    }

    private fun fill(): Boolean {
        var k = key
        if (k == null) {
            val salt = ByteArray(cr.saltLen)
            if (!fully(salt)) return false
            k = cr.subkey(salt); key = k
        }
        val lenBuf = ByteArray(2 + 16)
        if (!fully(lenBuf)) return false
        val l = cr.open(k, nonce, lenBuf); bump(nonce)
        val n = ((l[0].toInt() and 0xFF) shl 8) or (l[1].toInt() and 0xFF)
        if (n > 0x3FFF) throw IOException("Shadowsocks: bad chunk length (wrong password or cipher)")
        val body = ByteArray(n + 16)
        if (!fully(body)) throw IOException("Shadowsocks: connection cut mid-chunk")
        buf = cr.open(k, nonce, body); bump(nonce)
        pos = 0
        return true
    }

    override fun read(): Int {
        val b = ByteArray(1)
        val n = read(b, 0, 1)
        return if (n < 0) -1 else b[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        while (pos >= buf.size) { if (!fill()) return -1 }
        val n = minOf(len, buf.size - pos)
        System.arraycopy(buf, pos, b, off, n)
        pos += n
        return n
    }
}

/* ---------------------------------------------------------------- Engine */

/**
 * Shadowsocks / VLESS / Trojan client. Every SOCKS5 CONNECT from the TUN bridge becomes one
 * connection to the remote server (TCP, TLS with SNI, optionally inside a WebSocket).
 */
class JuanXEngine(
    private val c: JuanCfg,
    private val log: (String) -> Unit,
    private val protect: (Socket) -> Unit = {}
) : TunnelEngine {
    override val up = AtomicLong()
    override val down = AtomicLong()
    @Volatile override var probeError = ""
    @Volatile private var port = 0
    override val socksPort: Int get() = port

    private var server: ServerSocket? = null
    private val running = AtomicBoolean(false)
    private val failures = AtomicInteger(0)
    private val pool = Executors.newCachedThreadPool()
    @Volatile private var resolved: InetAddress? = null
    private val ss: SsCrypto? = if (c.xProto == "ss") SsCrypto(c.xMethod, c.xSecret) else null

    private fun proto() = when (c.xProto) { "ss" -> "Shadowsocks"; "trojan" -> "Trojan"; else -> "VLESS" } +
        (if (c.xNet == "ws") " + WebSocket" else "") + (if (c.xTls) " + TLS" else "")

    override fun start() {
        log("${proto()}: connecting ${c.xHost}:${c.xPort}")
        transport(false).close()
        log("${proto()}: server reachable, transport OK")
        val ssock = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        server = ssock; port = ssock.localPort; running.set(true)
        pool.execute {
            while (running.get()) try {
                val cl = ssock.accept()
                pool.execute { handle(cl) }
            } catch (_: Exception) { if (running.get()) running.set(false) }
        }
        log("Tunnel: local forwarder on 127.0.0.1:$port")
    }

    override fun alive() = running.get() && failures.get() < 12

    /** Opens the raw transport: TCP, then TLS (SNI), then WebSocket upgrade. */
    private fun transport(quiet: Boolean): Link {
        val s = Socket()
        protect(s)
        try {
            val addr = resolved ?: run {
                if (!quiet) log("DNS: resolving ${c.xHost}")
                InetAddress.getByName(c.xHost).also { resolved = it; if (!quiet) log("DNS: ${c.xHost} -> ${it.hostAddress}") }
            }
            s.connect(InetSocketAddress(addr, c.xPort), 15_000)
            s.tcpNoDelay = true
            s.soTimeout = 15_000
            if (!quiet) log("Proxy: TCP connected ${addr.hostAddress}:${c.xPort}")
            var sock: Socket = s
            if (c.xTls) {
                val name = c.xSni.ifBlank { c.xHost }
                if (!quiet) {
                    if (name.matches(Regex("[0-9.:]+"))) log("TLS: warning - SNI is an IP address; servers usually need a domain name here")
                    if (!c.verify) log("TLS: warning - certificate verification is OFF")
                    log("TLS: handshake, SNI=$name")
                }
                sock = tlsWrap(s, name, c.xPort, c.verify)
                if (!quiet) log("TLS: ${(sock as javax.net.ssl.SSLSocket).session.protocol}" + if (c.verify) ", certificate verified" else "")
            }
            var i: InputStream = BufferedInputStream(sock.getInputStream(), 16384)
            var o: OutputStream = sock.getOutputStream()
            if (c.xNet == "ws") {
                val key = android.util.Base64.encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) }, android.util.Base64.NO_WRAP)
                val hostHdr = c.xWsHost.ifBlank { c.xSni.ifBlank { c.xHost } }
                o.write(("GET ${c.xWsPath.ifBlank { "/" }} HTTP/1.1\r\nHost: $hostHdr\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n\r\n").toByteArray(Charsets.ISO_8859_1))
                o.flush()
                val head = StringBuilder()
                while (head.length < 8192 && !head.endsWith("\r\n\r\n")) {
                    val b = i.read()
                    if (b < 0) throw IOException("Proxy closed the connection during handshake")
                    head.append(b.toChar())
                }
                val first = head.toString().substringBefore("\r\n")
                if (first.split(" ").getOrNull(1) != "101") throw IOException("Proxy replied: $first")
                if (!quiet) log("Proxy: handshake OK ($first)")
                val ws = WsCodec(i, o)
                i = ws.input; o = ws.output
            }
            return Link(i, o, sock)
        } catch (e: Throwable) {
            try { s.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun addr(host: String, port: Int, vless: Boolean): ByteArray {
        val b = ByteArrayOutputStream()
        val v4 = Regex("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})").matches(host)
        val v6 = host.contains(':')
        if (vless) {
            // VLESS: port first, then type (1 ipv4, 2 domain, 3 ipv6)
            b.write(port shr 8); b.write(port and 0xFF)
            when {
                v4 -> { b.write(1); b.write(InetAddress.getByName(host).address) }
                v6 -> { b.write(3); b.write(InetAddress.getByName(host).address) }
                else -> { val h = host.toByteArray(); b.write(2); b.write(h.size); b.write(h) }
            }
        } else {
            // SOCKS5-style (Trojan, Shadowsocks): type (1 ipv4, 3 domain, 4 ipv6), address, port
            when {
                v4 -> { b.write(1); b.write(InetAddress.getByName(host).address) }
                v6 -> { b.write(4); b.write(InetAddress.getByName(host).address) }
                else -> { val h = host.toByteArray(); b.write(3); b.write(h.size); b.write(h) }
            }
            b.write(port shr 8); b.write(port and 0xFF)
        }
        return b.toByteArray()
    }

    private fun uuidBytes(): ByteArray {
        val hex = c.xSecret.replace("-", "")
        return ByteArray(16) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun openLink(host: String, port: Int, quiet: Boolean = true): Link {
        val t = transport(quiet)
        try {
            val i: InputStream
            val o: OutputStream
            when (c.xProto) {
                "trojan" -> {
                    val hash = MessageDigest.getInstance("SHA-224").digest(c.xSecret.toByteArray(Charsets.UTF_8))
                        .joinToString("") { "%02x".format(it) }
                    val req = ByteArrayOutputStream()
                    req.write(hash.toByteArray()); req.write("\r\n".toByteArray())
                    req.write(1); req.write(addr(host, port, false)); req.write("\r\n".toByteArray())
                    t.o.write(req.toByteArray()); t.o.flush()
                    i = t.i; o = t.o
                }
                "vless" -> {
                    val req = ByteArrayOutputStream()
                    req.write(0); req.write(uuidBytes()); req.write(0); req.write(1); req.write(addr(host, port, true))
                    t.o.write(req.toByteArray()); t.o.flush()
                    i = VlessIn(t.i); o = t.o
                }
                else -> {
                    val so = SsOut(t.o, ss!!)
                    so.write(addr(host, port, false)); so.flush()
                    i = SsIn(t.i, ss); o = so
                }
            }
            t.sock.soTimeout = 0
            return Link(i, o, t.sock)
        } catch (e: Throwable) { t.close(); throw e }
    }

    /** Real end-to-end check: fetch the first bytes of an HTTP reply through the remote server. */
    override fun probe(): Boolean = try {
        val l = openLink("1.1.1.1", 80, false)
        l.sock.soTimeout = 8000
        l.o.write("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\nUser-Agent: curl/8\r\n\r\n".toByteArray()); l.o.flush()
        val buf = ByteArray(8)
        var n = 0
        while (n < 5) { val r = l.i.read(buf, n, buf.size - n); if (r < 0) break; n += r }
        l.close()
        val ok = n >= 5 && String(buf, 0, n).startsWith("HTTP/")
        if (!ok) probeError = "The server accepted the connection but no data came back. Check the " +
            (if (c.xProto == "ss") "password and cipher" else if (c.xProto == "trojan") "password" else "UUID") +
            ", and that the server allows outbound traffic."
        ok
    } catch (e: Exception) {
        log("Probe failed: ${e.message}")
        probeError = "Connected to the server, but traffic could not pass: ${e.message}"
        false
    }

    private fun handle(cl: Socket) = cl.use { c0 ->
        val inp = DataInputStream(c0.getInputStream()); val out = c0.getOutputStream()
        var link: Link? = null
        try {
            if (inp.read() != 5) return@use
            repeat(inp.read()) { inp.read() }
            out.write(byteArrayOf(5, 0)); out.flush()
            inp.read(); val cmd = inp.read(); inp.read(); val atyp = inp.read()
            if (cmd != 1) { out.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0)); return@use }
            val host = when (atyp) {
                1 -> (1..4).joinToString(".") { inp.read().toString() }
                3 -> ByteArray(inp.read()).also { inp.readFully(it) }.toString(Charsets.UTF_8)
                4 -> InetAddress.getByAddress(ByteArray(16).also { inp.readFully(it) }).hostAddress ?: return@use
                else -> return@use
            }
            val tport = (inp.read() shl 8) or inp.read()
            val l = try { openLink(host, tport).also { failures.set(0) } } catch (e: Exception) {
                failures.incrementAndGet()
                out.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0)); return@use
            }
            link = l
            out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); out.flush()
            val t = pool.submit(Runnable {
                try {
                    val buf = ByteArray(16384)
                    while (true) { val n = inp.read(buf); if (n < 0) break; l.o.write(buf, 0, n); l.o.flush(); up.addAndGet(n.toLong()) }
                } catch (_: Exception) {}
                l.close()
            })
            try {
                val buf = ByteArray(16384)
                while (true) { val n = l.i.read(buf); if (n < 0) break; out.write(buf, 0, n); out.flush(); down.addAndGet(n.toLong()) }
            } catch (_: Exception) {}
            l.close(); try { c0.close() } catch (_: Exception) {}
            t.cancel(true)
        } catch (_: Exception) {
        } finally { link?.close() }
    }

    override fun stop() {
        running.set(false)
        try { server?.close() } catch (_: Exception) {}
        pool.shutdownNow()
    }
}
