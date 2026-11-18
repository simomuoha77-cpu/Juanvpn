package com.juanvpn.app

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import java.io.ByteArrayInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.ConcurrentHashMap
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private class CIn(val i: InputStream, val n: AtomicLong) : InputStream() {
    override fun read(): Int { val b = i.read(); if (b >= 0) n.incrementAndGet(); return b }
    override fun read(b: ByteArray, o: Int, l: Int): Int { val r = i.read(b, o, l); if (r > 0) n.addAndGet(r.toLong()); return r }
}
private class COut(val o: OutputStream, val n: AtomicLong) : OutputStream() {
    override fun write(b: Int) { o.write(b); n.incrementAndGet() }
    override fun write(b: ByteArray, off: Int, len: Int) { o.write(b, off, len); n.addAndGet(len.toLong()) }
    override fun flush() = o.flush()
}

/** SSH session (via JuanProxy) + local SOCKS5 that opens direct-tcpip channels. Counts real bytes. */
interface HostTrust {
    fun stored(label: String): String?
    fun confirm(host: String, type: String, fingerprint: String): Boolean
    fun save(line: String)
}

class JuanSshEngine(private val c: JuanCfg, private val log: (String) -> Unit, private val trust: HostTrust, private val protect: (Socket) -> Unit = {}) : TunnelEngine {
    @Volatile override var probeError = ""
    override val up = AtomicLong(); override val down = AtomicLong()
    @Volatile private var port = 0
    override val socksPort: Int get() = port
    private var session: Session? = null
    @Volatile private var proxy: JuanProxy? = null
    private var server: ServerSocket? = null
    private val running = AtomicBoolean(false)
    private val pool = Executors.newCachedThreadPool()

    override fun start() {
        val jsch = JSch()
        if (c.key.isNotBlank()) jsch.addIdentity("juan-key", c.key.toByteArray(), null, c.keyPass.takeIf { it.isNotEmpty() }?.toByteArray())
        val s = jsch.getSession(c.user, c.sshHost, c.sshPort)
        if (c.pass.isNotEmpty()) s.setPassword(c.pass)
        // Host keys are always accepted: no confirmation prompt and nothing to manage.
        s.setConfig("StrictHostKeyChecking", "no")
        // Keep the user's shorter interval, but cap very long values: after a network
        // handover a dead TCP path must be detected promptly so auto-reconnect can run.
        s.setServerAliveInterval(c.keepalive.coerceIn(10, 30) * 1000)
        s.setServerAliveCountMax(3)
        val px = JuanProxy(c, log, protect)
        proxy = px
        s.setProxy(px)
        log("SSH: connecting ${c.sshHost}:${c.sshPort}")
        s.connect(15_000)
        s.hostKey?.let { log("SSH: server key ${it.type} ${it.getFingerPrint(jsch)}") }
        log("SSH: AUTHENTICATED")
        session = s
        val ss = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        server = ss; port = ss.localPort; running.set(true)
        pool.execute { while (running.get()) try { val cl = ss.accept(); pool.execute { handle(cl, s) } } catch (_: Exception) { if (running.get()) running.set(false) } }
        log("Tunnel: local forwarder on 127.0.0.1:$port")
    }

    override fun alive() = running.get() && session?.isConnected == true

    private val extra = java.util.concurrent.CopyOnWriteArrayList<ServerSocket>()

    /** A local port that reaches host:port through this SSH session. Used to put V2Ray / Shadowsocks inside SSH. */
    fun forwardTo(host: String, rport: Int): Int {
        val s = session ?: throw IllegalStateException("SSH is not connected")
        val ss = ServerSocket(0, 64, InetAddress.getByName("127.0.0.1"))
        extra.add(ss)
        pool.execute { while (running.get()) try { val cl = ss.accept(); pool.execute { pipeTo(cl, s, host, rport) } } catch (_: Exception) { break } }
        return ss.localPort
    }

    private fun pipeTo(cl: Socket, ssh: Session, host: String, rport: Int) = cl.use { c0 ->
        try {
            val ch = ssh.openChannel("direct-tcpip") as ChannelDirectTCPIP
            ch.setHost(host); ch.setPort(rport)
            ch.setInputStream(CIn(c0.getInputStream(), up)); ch.setOutputStream(COut(c0.getOutputStream(), down))
            ch.connect(10_000)
            while (!ch.isClosed && !c0.isClosed) Thread.sleep(100)
            ch.disconnect()
        } catch (_: Exception) {}
    }

    /** Opens and closes a real channel through the SSH server. */
    override fun probe(): Boolean = try {
        val ch = session!!.openChannel("direct-tcpip") as ChannelDirectTCPIP
        ch.setHost("1.1.1.1"); ch.setPort(443); ch.connect(if (c.sshHost == "127.0.0.1") 25_000 else 8000)  // a DNS tunnel needs several slow round trips
        val ok = ch.isConnected; ch.disconnect(); ok
    } catch (e: Exception) {
        log("Probe failed: ${e.message}")
        probeError = if (e.message?.contains("prohibited", true) == true || e.message?.contains("open failed", true) == true)
            "SSH login worked, but the server refuses TCP forwarding. On the server set AllowTcpForwarding yes in sshd_config and restart sshd."
        else "SSH login worked, but traffic could not pass through the tunnel: ${e.message}"
        false
    }

    private fun handle(cl: Socket, ssh: Session) = cl.use { c0 ->
        val inp = DataInputStream(c0.getInputStream()); val out = c0.getOutputStream()
        try {
            if (inp.read() != 5) return@use
            repeat(inp.read()) { inp.read() }
            out.write(byteArrayOf(5, 0)); out.flush()
            inp.read(); val cmd = inp.read(); inp.read(); val atyp = inp.read()
            if (cmd != 1 && cmd != 3) { out.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0)); return@use }
            val host = when (atyp) {
                1 -> (1..4).joinToString(".") { inp.read().toString() }
                3 -> ByteArray(inp.read()).also { inp.readFully(it) }.toString(Charsets.UTF_8)
                4 -> InetAddress.getByAddress(ByteArray(16).also { inp.readFully(it) }).hostAddress
                else -> return@use
            }
            val port = (inp.read() shl 8) or inp.read()
            if (cmd == 3) {                                   // UDP ASSOCIATE
                if (!c.udpgw) { out.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0)); return@use }
                udpAssociate(c0, out, ssh)
                return@use
            }
            if (JuanPolicy.blocked(host, port)) { out.write(byteArrayOf(5, 2, 0, 1, 0, 0, 0, 0, 0, 0)); return@use }
            val ch = ssh.openChannel("direct-tcpip") as ChannelDirectTCPIP
            ch.setHost(host); ch.setPort(port)
            ch.setInputStream(CIn(inp, up)); ch.setOutputStream(COut(out, down))
            ch.connect(10_000)
            out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); out.flush()
            while (!ch.isClosed && !c0.isClosed) Thread.sleep(100)
            ch.disconnect()
        } catch (_: Exception) { try { out.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0)) } catch (_: Exception) {} }
    }

    // ---------- UDP over SSH (udpgw) ----------
    @Volatile private var udpgw: UdpGw? = null

    private fun udpAssociate(c0: Socket, out: OutputStream, ssh: Session) {
        val gw = udpgw ?: synchronized(this) { udpgw ?: UdpGw(ssh).also { udpgw = it } }
        val a = UdpAssoc(gw)
        try {
            val p = a.port()
            out.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, (p shr 8).toByte(), p.toByte())); out.flush()
            pool.execute { a.run() }
            val ins = c0.getInputStream()
            while (ins.read() >= 0) { /* the association lives as long as this TCP connection */ }
        } catch (_: Exception) {
        } finally { a.close() }
    }

    /** One shared channel to the server's UDP gateway (badvpn-udpgw, usually 127.0.0.1:7300 on the server). */
    private inner class UdpGw(private val ssh: Session) {
        private val lock = Any()
        private var out: OutputStream? = null
        private var ch: ChannelDirectTCPIP? = null
        @Volatile private var failedAt = 0L
        @Volatile private var warned = false
        val owners = ConcurrentHashMap<Int, UdpAssoc>()
        private val nextId = java.util.concurrent.atomic.AtomicInteger(1)

        fun newId(): Int { var id = nextId.getAndIncrement() and 0xFFFF; if (id == 0) id = nextId.getAndIncrement() and 0xFFFF; return id }

        private fun ensure(): OutputStream? = synchronized(lock) {
            val cur = out
            if (cur != null && ch?.isConnected == true) cur
            else if (System.currentTimeMillis() - failedAt < 30_000) null
            else try {
                val c1 = ssh.openChannel("direct-tcpip") as ChannelDirectTCPIP
                c1.setHost("127.0.0.1"); c1.setPort(c.udpgwPort)
                val i = c1.inputStream
                val o = c1.outputStream
                c1.connect(8000)
                ch = c1; out = o
                log("UDP: gateway ready")
                pool.execute { readLoop(i, c1) }
                o
            } catch (e: Exception) {
                failedAt = System.currentTimeMillis(); ch = null; out = null
                if (!warned) { warned = true; log("UDP: this server has no UDP gateway on port ${c.udpgwPort}") }
                null
            }
        }

        private fun readLoop(i: InputStream, c1: ChannelDirectTCPIP) {
            val din = DataInputStream(i)
            try {
                while (running.get()) {
                    val hb = ByteArray(2); din.readFully(hb)
                    val len = (hb[0].toInt() and 0xFF) or ((hb[1].toInt() and 0xFF) shl 8)
                    if (len < 3) break
                    val p = ByteArray(len); din.readFully(p)
                    val flags = p[0].toInt() and 0xFF
                    val id = (p[1].toInt() and 0xFF) or ((p[2].toInt() and 0xFF) shl 8)
                    val alen = if ((flags and 8) != 0) 16 else 4
                    if (len < 3 + alen + 2) continue
                    val ip = p.copyOfRange(3, 3 + alen)
                    val prt = ((p[3 + alen].toInt() and 0xFF) shl 8) or (p[4 + alen].toInt() and 0xFF)
                    val data = p.copyOfRange(5 + alen, len)
                    if ((flags and 1) != 0 && data.isEmpty()) continue      // keepalive
                    owners[id]?.deliver(ip, prt, data)
                }
            } catch (_: Exception) {
            } finally {
                synchronized(lock) { if (ch === c1) { out = null; ch = null } }
                try { c1.disconnect() } catch (_: Exception) {}
            }
        }

        fun send(id: Int, ip: ByteArray, port: Int, data: ByteArray): Boolean {
            if (data.size > 60_000) return false
            val o = ensure() ?: return false
            val body = 3 + ip.size + 2 + data.size
            val buf = ByteArray(2 + body)
            buf[0] = body.toByte(); buf[1] = (body shr 8).toByte()
            buf[2] = (if (ip.size == 16) 8 else 0).toByte()
            buf[3] = id.toByte(); buf[4] = (id shr 8).toByte()
            System.arraycopy(ip, 0, buf, 5, ip.size)
            buf[5 + ip.size] = (port shr 8).toByte(); buf[6 + ip.size] = port.toByte()
            System.arraycopy(data, 0, buf, 7 + ip.size, data.size)
            return try {
                synchronized(lock) { o.write(buf); o.flush() }
                up.addAndGet(data.size.toLong()); true
            } catch (_: Exception) { synchronized(lock) { if (out === o) out = null }; false }
        }

        fun close() { synchronized(lock) { try { ch?.disconnect() } catch (_: Exception) {}; ch = null; out = null }; owners.clear() }
    }

    /** One SOCKS5 UDP association: datagrams from the packet engine become udpgw packets and back. */
    private inner class UdpAssoc(private val gw: UdpGw) {
        private val sock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        @Volatile private var client: java.net.InetSocketAddress? = null
        private val ids = HashMap<String, Int>()

        fun port() = sock.localPort

        fun run() {
            val buf = ByteArray(65535)
            val pk = DatagramPacket(buf, buf.size)
            while (!sock.isClosed) {
                pk.length = buf.size
                try { sock.receive(pk) } catch (_: Exception) { break }
                client = pk.socketAddress as? java.net.InetSocketAddress
                val n = pk.length
                if (n < 10 || buf[2].toInt() != 0) continue                 // fragments are not supported
                val ip: ByteArray; val prt: Int; val off: Int
                when (buf[3].toInt()) {
                    1 -> { ip = buf.copyOfRange(4, 8); prt = ((buf[8].toInt() and 0xFF) shl 8) or (buf[9].toInt() and 0xFF); off = 10 }
                    4 -> { if (n < 22) continue; ip = buf.copyOfRange(4, 20); prt = ((buf[20].toInt() and 0xFF) shl 8) or (buf[21].toInt() and 0xFF); off = 22 }
                    else -> continue
                }
                val key = ip.joinToString(",") + ":" + prt
                val id = synchronized(ids) { ids.getOrPut(key) { gw.newId().also { gw.owners[it] = this } } }
                gw.send(id, ip, prt, buf.copyOfRange(off, n))
            }
        }

        fun deliver(ip: ByteArray, port: Int, data: ByteArray) {
            val cl = client ?: return
            val h = ByteArray(4 + ip.size + 2 + data.size)
            h[3] = (if (ip.size == 16) 4 else 1).toByte()
            System.arraycopy(ip, 0, h, 4, ip.size)
            h[4 + ip.size] = (port shr 8).toByte(); h[5 + ip.size] = port.toByte()
            System.arraycopy(data, 0, h, 6 + ip.size, data.size)
            try { sock.send(DatagramPacket(h, h.size, cl)); down.addAndGet(data.size.toLong()) } catch (_: Exception) {}
        }

        fun close() {
            try { sock.close() } catch (_: Exception) {}
            synchronized(ids) { ids.values.forEach { gw.owners.remove(it) }; ids.clear() }
        }
    }

    override fun stop() {
        try { udpgw?.close() } catch (_: Exception) {}
        running.set(false)
        try { proxy?.cancel() } catch (_: Exception) {}      // aborts a handshake that is still in progress
        try { server?.close() } catch (_: Exception) {}
        extra.forEach { try { it.close() } catch (_: Exception) {} }
        try { session?.disconnect() } catch (_: Exception) {}
        pool.shutdownNow()
    }

    companion object {
        fun transient(e: Throwable): Boolean {
            val m = ((e.message ?: "") + " " + (e.cause?.message ?: "")).lowercase()
            val hardStop = m.contains("auth fail") || m.contains("auth cancel") || m.contains("userauth") ||
                m.contains("hostkey") || m.contains("host key") || m.contains("algorithm negotiation") ||
                m.contains("uuid") || m.contains("unsupported shadowsocks") || m.contains("requires tls")
            if (hardStop) return false
            // Everything else (proxy 4xx/5xx, SOCKS4/5 rejections, TLS/handshake mismatches, resets,
            // timeouts, "no connection candidate") is worth retrying: the rotation index advances each
            // call, so the next attempt tries a different proxy/SNI/payload automatically.
            return true
        }

        fun friendly(e: Throwable): String {
            val m = e.message ?: e.javaClass.simpleName
            return when {
                m.contains("reject HostKey", true) -> "SSH host key rejected: it does not match the record in Known hosts. Confirm the correct key with the server admin; do not trust it blindly."
                m.contains("changed", true) && m.contains("HostKey", true) -> "SERVER HOST KEY CHANGED: this is not the server you trusted before. Do not continue unless the server admin confirms a key change."
                m.contains("Algorithm negotiation fail", true) && m.contains("server_host_key") -> "The server's host key type differs from the saved one. Tap 'Forget trusted key' on the SSH server screen and connect again."
                m.contains("Algorithm negotiation fail", true) -> "No common SSH algorithm with this server ($m)"
                Regex("^Proxy replied: HTTP/\\d\\.\\d 52\\d").containsMatchIn(m) -> "The CDN/proxy in front of your server returned ${m.substringAfter("Proxy replied: HTTP/").substringAfter(" ").take(3)} (it could not get a good answer from the server behind it). This is usually temporary; the app retries automatically. If it never connects, the server behind the proxy is down or overloaded."
                Regex("^Proxy replied: HTTP/\\d\\.\\d 407").containsMatchIn(m) -> "The proxy needs a username and password (407). Set them under Remote proxy username and password."
                Regex("^Proxy replied: HTTP/\\d\\.\\d 5").containsMatchIn(m) -> "The proxy front returned a temporary server error ($m). The server behind it may be down or busy."
                Regex("^Proxy replied: HTTP/\\d\\.\\d 421").containsMatchIn(m) -> "The server says the SNI and the Host header do not match (421). Make the Host in your payload the same name as the SNI, or add more SNI/payload entries so the app can rotate."
                Regex("^Proxy replied: HTTP/\\d\\.\\d 403").containsMatchIn(m) -> "The server refused the payload (403). Check the Host header and path, or add more payloads (separate them with a line of ---) so the app can rotate."
                Regex("^Proxy replied: HTTP/\\d\\.\\d 4").containsMatchIn(m) -> "The server refused the request ($m). Check the WebSocket path, the Host header and the payload."
                m.contains("Unable to parse TLS packet", true) -> "That port is not TLS. Use the TLS port (usually 443), or switch Connect from to HTTP proxy."
                m.contains("HANDSHAKE_FAILURE", true) -> "The TLS server rejected the handshake. It may need a domain-name SNI (an IP address cannot be used), or it does not speak TLS on this port."
                m.contains("ENETUNREACH", true) -> "No network path to the server. Check your internet connection."
                m.contains("UnknownHostKey", true) -> "Unknown SSH host key: add the server's verified known_hosts record."
                m.contains("Auth fail", true) || m.contains("Auth cancel", true) -> "SSH authentication failed: wrong username, password or key."
                e is java.net.UnknownHostException -> "Cannot resolve host: $m"
                e is javax.net.ssl.SSLException -> "TLS failed: $m"
                m.contains("timeout", true) || m.contains("timed out", true) -> "Connection timed out: host or port unreachable."
                else -> m
            }
        }
    }
}
