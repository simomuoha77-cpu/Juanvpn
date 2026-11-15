package com.juanvpn.app

import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Local SOCKS5 endpoint. Each CONNECT request becomes an authenticated SSH direct-tcpip channel. */
class SshSocksServer(private val profile: Profile) {
    private val running = AtomicBoolean(false)
    private val pool = Executors.newCachedThreadPool()
    private var listener: ServerSocket? = null
    private var session: Session? = null

    fun start() {
        require(profile.sshHost.isNotBlank() && profile.username.isNotBlank()) { "SSH host and username are required" }
        val jsch = JSch()
        require(profile.knownHosts.isNotBlank()) { "Add the verified SSH host-key line in Known Hosts before connecting" }
        jsch.setKnownHosts(ByteArrayInputStream(profile.knownHosts.toByteArray()))
        if (profile.privateKey.isNotBlank()) jsch.addIdentity("juan-imported-key", profile.privateKey.toByteArray(), null, null)
        val s = jsch.getSession(profile.username, profile.sshHost, profile.sshPort)
        if (profile.password.isNotBlank()) s.setPassword(profile.password)
        s.setConfig("StrictHostKeyChecking", "yes")
        s.connect(15_000)
        session = s
        listener = ServerSocket(profile.socksPort, 64, java.net.InetAddress.getByName("127.0.0.1"))
        running.set(true)
        pool.execute { while (running.get()) try { val client = listener!!.accept(); pool.execute { handle(client, s) } } catch (_: Exception) { if (running.get()) stop() } }
    }

    private fun handle(client: Socket, ssh: Session) {
        client.use { c ->
            val input = DataInputStream(BufferedInputStream(c.getInputStream())); val output = BufferedOutputStream(c.getOutputStream())
            try {
                val ver = input.read(); val n = input.read(); if (ver != 5 || n < 1) return
                repeat(n) { input.read() }; output.write(byteArrayOf(5, 0)); output.flush()
                val h = input.read(); val cmd = input.read(); input.read(); val atyp = input.read()
                if (h != 5 || cmd != 1) { output.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0)); output.flush(); return }
                val host = when (atyp) {
                    1 -> (1..4).joinToString(".") { input.read().toString() }
                    3 -> ByteArray(input.read()).also { input.readFully(it) }.toString(Charsets.UTF_8)
                    4 -> ByteArray(16).also { input.readFully(it) }.joinToString(":") { "%02x".format(it) }
                    else -> return
                }
                val port = (input.read() shl 8) or input.read()
                val channel = ssh.openChannel("direct-tcpip") as com.jcraft.jsch.ChannelDirectTCPIP
                channel.setHost(host); channel.setPort(port); channel.setInputStream(input); channel.setOutputStream(output)
                channel.connect(10_000)
                output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); output.flush()
                while (!channel.isClosed && !c.isClosed) Thread.sleep(100)
                channel.disconnect()
            } catch (_: Exception) { try { output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0)); output.flush() } catch (_: Exception) {} }
        }
    }
    fun stop() { running.set(false); try { listener?.close() } catch (_: Exception) {}; try { session?.disconnect() } catch (_: Exception) {}; pool.shutdownNow() }
}
