package com.juanvpn.app

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Hysteria 2 (QUIC). The Hysteria client runs as its own program and offers a local SOCKS5 port, with UDP, which the
 * TUN engine then uses like any other engine. Traffic counters come from the TUN engine.
 */
class JuanHyEngine(
    private val ctx: Context,
    private val c: JuanCfg,
    private val log: (String) -> Unit
) : TunnelEngine {
    override val up = AtomicLong()
    override val down = AtomicLong()
    private var port = 0
    override val socksPort: Int get() = port
    override var probeError: String = ""
    private val proc = JuanProcess("hysteria")
    private val running = AtomicBoolean(false)
    private var cfgFile: File? = null

    private fun q(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ") + "\""

    override fun start() {
        val bin = JuanProc.binary(ctx, "hysteria") ?: throw JuanFatalException("The Hysteria engine is not included in this build")
        port = JuanProc.freePort()
        val host = if (c.hyHost.contains(':') && !c.hyHost.startsWith("[")) "[${c.hyHost}]" else c.hyHost
        val y = StringBuilder()
        y.append("server: ").append(q("$host:${c.hyPort}")).append('\n')
        y.append("auth: ").append(q(c.hyAuth)).append('\n')
        y.append("tls:\n")
        if (c.hySni.isNotBlank()) y.append("  sni: ").append(q(c.hySni)).append('\n')
        y.append("  insecure: ").append(c.hyInsecure).append('\n')
        if (c.hyObfs.isNotBlank()) y.append("obfs:\n  type: salamander\n  salamander:\n    password: ").append(q(c.hyObfs)).append('\n')
        if (c.hyUp > 0 || c.hyDown > 0) {
            y.append("bandwidth:\n")
            if (c.hyUp > 0) y.append("  up: ${c.hyUp} mbps\n")
            if (c.hyDown > 0) y.append("  down: ${c.hyDown} mbps\n")
        }
        y.append("socks5:\n  listen: 127.0.0.1:$port\n")
        y.append("fastOpen: true\n")
        val f = File(ctx.noBackupFilesDir, "hy-$port.yaml")
        cfgFile = f
        f.writeText(y.toString())
        try { f.setReadable(false, false); f.setReadable(true, true) } catch (_: Exception) {}

        log("Hysteria: connecting")
        proc.onLine = { l -> handle(l) }
        proc.start(listOf(bin.path, "client", "-c", f.path), ctx)

        val end = System.currentTimeMillis() + 20000
        var ok = false
        while (System.currentTimeMillis() < end) {
            if (!proc.alive()) break
            if (JuanProc.portOpen(port)) { ok = true; break }
            Thread.sleep(250)
        }
        try { f.delete() } catch (_: Exception) {}     // the password is no longer needed on disk
        if (!ok) {
            val why = explain(proc.lines())
            stop()
            throw JuanConnException(JuanFail.OTHER, why)
        }
        running.set(true)
        Thread {
            while (running.get()) {
                val s = TunEngine.stats()
                if (s != null && s.size >= 4) { up.set(s[1]); down.set(s[3]) }
                try { Thread.sleep(1000) } catch (_: InterruptedException) { return@Thread }
            }
        }.also { it.name = "JuanHyStats"; it.isDaemon = true }.start()
    }

    private fun handle(l: String) {
        val p = l.split('\t')
        if (p.size < 3) return
        val lvl = p[1].trim().uppercase()
        val msg = p[2].trim()
        if (msg.contains("connected to server")) log("Hysteria: connected to server")
        else if (lvl == "WARN" || lvl == "ERROR" || lvl == "FATAL") log("Hysteria: " + msg.take(100))
    }

    private fun explain(lines: List<String>): String {
        val t = lines.joinToString("\n").lowercase()
        return when {
            "auth" in t && ("fail" in t || "error" in t || "denied" in t) -> "Hysteria login failed. Check the password."
            "certificate" in t || "x509" in t || ("tls" in t && "verify" in t) -> "The TLS certificate check failed. Check the SNI, or turn on Allow insecure."
            "timeout" in t || "no recent network activity" in t || "deadline" in t -> "The Hysteria server did not answer. Check the address and port, and that UDP is allowed on this network."
            "no such host" in t || "lookup" in t -> "Could not resolve the Hysteria server address."
            t.isBlank() -> "The Hysteria engine stopped before it connected."
            else -> "Hysteria could not connect: " + (lines.lastOrNull { it.contains('\t') }?.split('\t')?.getOrNull(2) ?: lines.last()).take(100)
        }
    }

    override fun alive() = running.get() && proc.alive()

    override fun probe(): Boolean {
        val ok = JuanProc.socksProbe(port)
        if (!ok) probeError = "Connected to the Hysteria server, but no traffic passed. Check that the server allows outbound traffic."
        return ok
    }

    override fun stop() {
        running.set(false)
        proc.close()
        try { cfgFile?.delete() } catch (_: Exception) {}
    }
}

/** DNSTT: carries one TCP connection (SSH or V2Ray) inside DNS queries. Offers a local TCP port. */
class JuanDnsttRunner(
    private val ctx: Context,
    private val c: JuanCfg,
    private val log: (String) -> Unit
) : java.io.Closeable {
    private val proc = JuanProcess("dnstt")

    fun start(): Int {
        val bin = JuanProc.binary(ctx, "dnstt") ?: throw JuanFatalException("The DNSTT engine is not included in this build")
        val port = JuanProc.stablePort(c.dnsDomain)
        val key = File(ctx.noBackupFilesDir, "dnstt.pub")
        key.writeText(c.dnsKey + "\n")
        val (flag, def) = when (c.dnsMode) {
            "doh" -> "-doh" to "https://dns.google/dns-query"
            "dot" -> "-dot" to "dns.google:853"
            else -> "-udp" to "8.8.8.8:53"
        }
        log("DNS tunnel: starting")
        proc.onLine = { l -> if (l.lowercase().contains("error")) log("DNS tunnel: " + l.substringAfter(' ').substringAfter(' ').take(100)) }
        proc.start(listOf(bin.path, flag, c.dnsResolver.ifBlank { def }, "-pubkey-file", key.path, c.dnsDomain, "127.0.0.1:$port"), ctx)
        val end = System.currentTimeMillis() + 8000
        var ok = false
        while (System.currentTimeMillis() < end) {
            if (!proc.alive()) break
            if (JuanProc.portOpen(port)) { ok = true; break }
            Thread.sleep(200)
        }
        try { key.delete() } catch (_: Exception) {}
        if (!ok) {
            val last = proc.lines().lastOrNull { it.isNotBlank() }?.take(100) ?: "the engine stopped"
            close()
            throw JuanConnException(JuanFail.OTHER, "The DNS tunnel could not start: $last")
        }
        log("DNS tunnel: ready")
        return port
    }

    override fun close() { proc.close() }
}
