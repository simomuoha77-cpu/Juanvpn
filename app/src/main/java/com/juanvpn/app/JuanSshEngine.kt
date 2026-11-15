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
class JuanSshEngine(private val c: JuanCfg, private val log: (String) -> Unit) {
    val up = AtomicLong(); val down = AtomicLong()
    @Volatile var socksPort = 0; private set
    private var session: Session? = null
    private var server: ServerSocket? = null
    private val running = AtomicBoolean(false)
    private val pool = Executors.newCachedThreadPool()

    fun start() {
        val known = HostKeys.normalize(c.sshHost, c.sshPort, c.known)
        val types = HostKeys.types(known)
        require(types.isNotEmpty()) { "Host key missing: paste the full known_hosts record" }
        val jsch = JSch()
        jsch.setKnownHosts(ByteArrayInputStream(known.toByteArray()))
        if (c.key.isNotBlank()) jsch.addIdentity("juan-key", c.key.toByteArray(), null, c.keyPass.takeIf { it.isNotEmpty() }?.toByteArray())
        val s = jsch.getSession(c.user, c.sshHost, c.sshPort)
        if (c.pass.isNotEmpty()) s.setPassword(c.pass)
        s.setConfig("StrictHostKeyChecking", "yes")
        s.setConfig("server_host_key", HostKeys.algorithms(types))
        s.setServerAliveInterval(c.keepalive * 1000)
        s.setServerAliveCountMax(3)
        s.setProxy(JuanProxy(c, log))
        log("SSH: connecting ${c.sshHost}:${c.sshPort} (host key types: ${types.joinToString()})")
        s.connect(20_000)
        log("SSH: authenticated as ${c.user}")
        session = s
        val ss = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        server = ss; socksPort = ss.localPort; running.set(true)
        pool.execute { while (running.get()) try { val cl = ss.accept(); pool.execute { handle(cl, s) } } catch (_: Exception) { if (running.get()) running.set(false) } }
        log("Tunnel: local forwarder on 127.0.0.1:$socksPort")
    }

    fun alive() = running.get() && session?.isConnected == true

    /** Opens and closes a real channel through the SSH server. */
    fun probe(): Boolean = try {
        val ch = session!!.openChannel("direct-tcpip") as ChannelDirectTCPIP
        ch.setHost("1.1.1.1"); ch.setPort(443); ch.connect(8000)
        val ok = ch.isConnected; ch.disconnect(); ok
    } catch (e: Exception) { log("Probe failed: ${e.message}"); false }

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
            val ch = ssh.openChannel("direct-tcpip") as ChannelDirectTCPIP
            ch.setHost(host); ch.setPort(port)
            ch.setInputStream(CIn(inp, up)); ch.setOutputStream(COut(out, down))
            ch.connect(10_000)
            out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); out.flush()
            while (!ch.isClosed && !c0.isClosed) Thread.sleep(100)
            ch.disconnect()
        } catch (_: Exception) { try { out.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0)) } catch (_: Exception) {} }
    }

    fun stop() {
        running.set(false)
        try { server?.close() } catch (_: Exception) {}
        try { session?.disconnect() } catch (_: Exception) {}
        pool.shutdownNow()
    }

    companion object {
        fun friendly(e: Throwable): String {
            val m = e.message ?: e.javaClass.simpleName
            return when {
                m.contains("reject HostKey", true) -> "SSH host key rejected: it does not match the record in Known hosts. Confirm the correct key with the server admin; do not trust it blindly."
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
