package com.juanvpn.app

import android.util.Base64
import com.jcraft.jsch.Proxy
import com.jcraft.jsch.SocketFactory
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** TLS with SNI. Certificate chain and hostname are always verified. */
fun tlsWrap(plain: Socket, sni: String, port: Int): SSLSocket {
    val s = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(plain, sni, port, true) as SSLSocket
    s.enabledProtocols = s.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
    s.startHandshake()
    if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(sni, s.session))
        throw SSLPeerUnverifiedException("Certificate does not match server name '$sni'")
    return s
}

private fun fill(t: String, host: String, port: Int) =
    t.replace("[host_port]", "$host:$port").replace("[host]", host)
        .replace("[crlf]", "\r\n").replace("[cr]", "\r").replace("[lf]", "\n")

/** Real upstream transport for SSH: direct, HTTP CONNECT/payload, SOCKS5, TLS(+SNI)+payload, WebSocket upgrade. */
class JuanProxy(private val c: JuanCfg, private val log: (String) -> Unit, private val protect: (Socket) -> Unit = {}) : Proxy {
    private var sock: Socket? = null
    private var ins: InputStream? = null
    private var outs: OutputStream? = null

    override fun connect(sf: SocketFactory?, host: String, port: Int, timeout: Int) {
        val viaProxy = c.from != "direct" && c.pHost.isNotBlank()
        val th = if (viaProxy) c.pHost else host
        val tp = if (viaProxy) c.pPort else port
        log("DNS: resolving $th")
        val addr = InetAddress.getByName(th)
        log("DNS: $th -> ${addr.hostAddress}")
        var s = Socket()
        protect(s)
        s.connect(InetSocketAddress(addr, tp), timeout)
        s.soTimeout = timeout
        s.tcpNoDelay = true
        log("Proxy: TCP connected ${addr.hostAddress}:$tp (${c.from})")
        if (c.from == "tls" || (c.from == "ws" && c.sni.isNotBlank())) {
            val name = c.sni.ifBlank { th }
            if (name.matches(Regex("[0-9.:]+"))) log("TLS: warning - SNI is an IP address; servers usually need a domain name here")
            log("TLS: handshake, SNI=$name")
            val ssl = tlsWrap(s, name, tp)
            log("TLS: ${ssl.session.protocol} ${ssl.session.cipherSuite}, certificate verified")
            s = ssl
        }
        val i = s.getInputStream()
        val o = s.getOutputStream()
        val custom = c.custom && c.payload.isNotBlank()
        when (c.from) {
            "http" -> {
                val auth = if (c.pUser.isNotEmpty()) "Proxy-Authorization: Basic " +
                    Base64.encodeToString("${c.pUser}:${c.pPass}".toByteArray(), Base64.NO_WRAP) + "\r\n" else ""
                send(o, if (custom) payloadReq(host, port)
                else "CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\n$auth\r\n")
                expectOk(readHead(i))
            }
            "socks5" -> socks5(i, o, host, port)
            "tls" -> if (custom) { send(o, payloadReq(host, port)); expectOk(readHead(i)) }
            "ws" -> {
                val key = Base64.encodeToString(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }, Base64.NO_WRAP)
                send(o, if (custom) payloadReq(host, port)
                else "GET ${c.wsPath.ifBlank { "/" }} HTTP/1.1\r\nHost: ${c.sni.ifBlank { host }}\r\nUpgrade: websocket\r\n" +
                    "Connection: Upgrade\r\nSec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n\r\n")
                expectOk(readHead(i))
            }
        }
        s.soTimeout = 0
        sock = s; ins = i; outs = o
    }

    private fun payloadReq(host: String, port: Int): String {
        val full = fill(c.payload, host, port)
        val i = full.indexOf("\r\n\r\n")
        if (i >= 0 && i + 4 < full.length) log("Payload: text after the first blank line was ignored")
        return if (i >= 0) full.substring(0, i + 4) else full
    }

    private fun send(o: OutputStream, req: String) {
        o.write((if (req.endsWith("\r\n\r\n")) req else req + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1)); o.flush()
    }

    private fun readHead(i: InputStream): String {
        val sb = StringBuilder()
        while (sb.length < 8192) {
            val b = i.read()
            if (b < 0) throw IOException("Proxy closed the connection during handshake")
            sb.append(b.toChar())
            if (sb.endsWith("\r\n\r\n")) return sb.toString()
        }
        throw IOException("Proxy response too large")
    }

    private fun expectOk(head: String) {
        val first = head.substringBefore("\r\n")
        val code = first.split(" ").getOrNull(1)?.toIntOrNull()
        if (code != 101 && (code == null || code !in 200..299)) throw IOException("Proxy replied: $first")
        log("Proxy: handshake OK ($first)")
    }

    private fun socks5(i: InputStream, o: OutputStream, host: String, port: Int) {
        val auth = c.pUser.isNotEmpty()
        o.write(if (auth) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0)); o.flush()
        val m = ByteArray(2).also { readFully(i, it) }
        if (m[0].toInt() != 5 || (m[1].toInt() and 0xFF) == 0xFF) throw IOException("SOCKS5 proxy rejected authentication methods")
        if (m[1].toInt() == 2) {
            val u = c.pUser.toByteArray(); val p = c.pPass.toByteArray()
            o.write(byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p); o.flush()
            val r = ByteArray(2).also { readFully(i, it) }
            if (r[1].toInt() != 0) throw IOException("SOCKS5 proxy credentials rejected")
        }
        val h = host.toByteArray()
        o.write(byteArrayOf(5, 1, 0, 3, h.size.toByte()) + h + byteArrayOf((port shr 8).toByte(), port.toByte())); o.flush()
        val r = ByteArray(4).also { readFully(i, it) }
        if (r[1].toInt() != 0) throw IOException("SOCKS5 connect failed (code ${r[1]})")
        val skip = when (r[3].toInt()) { 1 -> 6; 4 -> 18; else -> i.read() + 2 }
        readFully(i, ByteArray(skip))
        log("Proxy: SOCKS5 CONNECT OK")
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
