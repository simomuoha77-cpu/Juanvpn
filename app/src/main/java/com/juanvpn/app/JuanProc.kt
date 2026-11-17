package com.juanvpn.app

import android.content.Context
import java.io.Closeable
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Helpers for the optional engines that run as separate programs next to the app (Hysteria, DNSTT).
 * The programs are built by the GitHub workflow into jniLibs as libhysteria.so / libdnstt.so and are started from
 * the app's native library folder. The app is excluded from the VPN, so these programs reach the internet directly.
 */
object JuanProc {
    fun binary(ctx: Context, name: String): File? =
        File(ctx.applicationInfo.nativeLibraryDir, "lib$name.so").takeIf { it.isFile }

    fun freePort(): Int = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

    /** Same local port every time for the same name, so SSH host-key pins keep matching. Falls back to any free port. */
    fun stablePort(seed: String): Int {
        val p = 30000 + (seed.hashCode() and 0x7fffffff) % 20000
        return try { ServerSocket(p, 1, InetAddress.getByName("127.0.0.1")).use { p } } catch (_: Exception) { freePort() }
    }

    fun portOpen(port: Int, ms: Int = 300): Boolean = try {
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), ms); true }
    } catch (_: Exception) { false }

    /** A real HTTP request through the local SOCKS5 port. True only when an answer came back. */
    fun socksProbe(port: Int): Boolean = try { JuanPing.viaSocks(port, "http://1.1.1.1/"); true } catch (_: Exception) { false }
}

/** One external program. Its output is kept (last lines only) so a failure can be explained clearly. */
class JuanProcess(private val name: String) : Closeable {
    private var p: Process? = null
    private val tail = java.util.ArrayDeque<String>()
    @Volatile var onLine: ((String) -> Unit)? = null

    fun start(cmd: List<String>, ctx: Context) {
        val pb = ProcessBuilder(cmd).redirectErrorStream(true)
        pb.directory(ctx.noBackupFilesDir)
        pb.environment().apply {
            put("HOME", ctx.noBackupFilesDir.path)
            put("TMPDIR", ctx.cacheDir.path)
            put("GODEBUG", "netdns=cgo")      // use the phone's own resolver
        }
        val pr = pb.start()
        p = pr
        Thread {
            try {
                pr.inputStream.bufferedReader().forEachLine { l ->
                    synchronized(tail) { tail.add(l); while (tail.size > 40) tail.removeFirst() }
                    try { onLine?.invoke(l) } catch (_: Throwable) {}
                }
            } catch (_: Exception) {}
        }.also { it.name = "JuanProc-$name"; it.isDaemon = true }.start()
    }

    fun alive(): Boolean {
        val pr = p ?: return false
        return try { pr.exitValue(); false } catch (_: IllegalThreadStateException) { true }
    }

    fun lines(): List<String> = synchronized(tail) { tail.toList() }

    override fun close() {
        val pr = p ?: return
        p = null
        try { pr.destroy() } catch (_: Exception) {}
        Thread { try { Thread.sleep(800); pr.destroyForcibly() } catch (_: Exception) {} }.also { it.isDaemon = true }.start()
    }
}
