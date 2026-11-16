package com.juanvpn.app

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import java.io.ByteArrayInputStream
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
        s.setServerAliveInterval(c.keepalive * 1000)
        s.setServerAliveCountMax(3)
        s.setProxy(JuanProxy(c, log, protect))
        log("SSH: connecting ${c.sshHost}:${c.sshPort}")
        s.connect(20_000)
        s.hostKey?.let { log("SSH: server key ${it.type} ${it.getFingerPrint(jsch)}") }
        log("SSH: authenticated as ${c.user}")
        session = s
        val ss = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        server = ss; port = ss.localPort; running.set(true)
        pool.execute { while (running.get()) try { val cl = ss.accept(); pool.execute { handle(cl, s) } } catch (_: Exception) { if (running.get()) running.set(false) } }
        log("Tunnel: local forwarder on 127.0.0.1:$port")
    }

    override fun alive() = running.get() && session?.isConnected == true

    /** Opens and closes a real channel through the SSH server. */
    override fun probe(): Boolean = try {
        val ch = session!!.openChannel("direct-tcpip") as ChannelDirectTCPIP
        ch.setHost("1.1.1.1"); ch.setPort(443); ch.connect(8000)
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
            if (cmd != 1) { out.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0)); return@use }
            val host = when (atyp) {
                1 -> (1..4).joinToString(".") { inp.read().toString() }
                3 -> ByteArray(inp.read()).also { inp.readFully(it) }.toString(Charsets.UTF_8)
                4 -> InetAddress.getByAddress(ByteArray(16).also { inp.readFully(it) }).hostAddress
                else -> return@use
            }
            val port = (inp.read() shl 8) or inp.read()
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

    override fun stop() {
        running.set(false)
        try { server?.close() } catch (_: Exception) {}
        try { session?.disconnect() } catch (_: Exception) {}
        pool.shutdownNow()
    }

    companion object {
        fun transient(e: Throwable): Boolean {
            val m = ((e.message ?: "") + " " + (e.cause?.message ?: "")).lowercase()
            if (m.contains("auth") || m.contains("hostkey") || m.contains("host key") || m.contains("algorithm")) return false
            return Regex("proxy replied: http/\\d\\.\\d (5\\d\\d|429)").containsMatchIn(m) || m.contains("websocket closed") || m.contains("proxy closed") || m.contains("closed by foreign host") ||
                m.contains("timed out") || m.contains("timeout") || m.contains("connection reset") || m.contains("eof") ||
                m.contains("socket closed") || m.contains("broken pipe") || m.contains("connection closed")
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
