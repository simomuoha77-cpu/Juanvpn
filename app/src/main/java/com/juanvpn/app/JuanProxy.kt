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
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

private val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
    override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
    override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
})

/**
 * TLS with SNI. By default the certificate chain and hostname are verified; verify=false is an explicit user choice
 * (or the hybrid fallback in [JuanProxy] for a borrowed SNI). [verifyAs] checks the certificate against another name
 * than the one sent as SNI, e.g. the real SSH server when the SNI is a front domain.
 */
fun tlsWrap(plain: Socket, sni: String, port: Int, verify: Boolean = true, verifyAs: String? = null): SSLSocket {
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
    val checkName = verifyAs ?: sni
    if (verify && !HttpsURLConnection.getDefaultHostnameVerifier().verify(checkName, s.session))
        throw SSLPeerUnverifiedException("Certificate does not match server name '$checkName'")
    return s
}

/** Internal: the strict handshake failed only because of the certificate. */
private class CertMismatch(val real: javax.net.ssl.SSLException) : javax.net.ssl.SSLException(real.message, real)

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
    private val RANDOM_UA = listOf(
        UA,
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
    )
    private val KNOWN_TAGS = setOf("crlf", "cr", "lf", "lfcr", "tab", "space", "host", "ssh_host", "host_ip", "ip", "port", "ssh_port",
        "host_port", "ssh", "protocol", "method", "netdata", "raw", "realdata", "real_raw", "rawdata", "ua", "user_agent", "random_ua",
        "ua_random", "sni", "proxy", "proxy_host", "proxy_port", "sni_rotate", "path", "ws_path", "wspath", "auth", "rotate", "random",
        "split", "instant_split", "split_instant", "delay_split", "split_delay", "delay")
    private val tag = Regex("\\[([A-Za-z_][A-Za-z0-9_-]*)(?:=([^\\]]*))?\\]")
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
            val name = m.groupValues[1].lowercase().replace('-', '_')
            val arg = m.groupValues[2]
            when (name) {
                "crlf" -> "\r\n"; "cr" -> "\r"; "lf" -> "\n"; "lfcr" -> "\n\r"; "tab" -> "\t"; "space" -> " "
                "host", "ssh_host", "host_ip", "ip" -> host
                "port", "ssh_port" -> port.toString()
                "host_port", "ssh" -> hp
                "protocol" -> "HTTP/1.1"
                "method" -> "CONNECT"
                "netdata", "raw", "realdata", "real_raw", "rawdata" -> "CONNECT $hp HTTP/1.1"
                "ua", "user_agent" -> UA
                "random_ua", "ua_random" -> RANDOM_UA[rnd.nextInt(RANDOM_UA.size)]
                "sni" -> sni.ifBlank { host }
                "proxy", "proxy_host" -> c.pHost
                "proxy_port" -> c.pPort.toString()
                "sni_rotate" -> sni.ifBlank { host }
                "path", "ws_path", "wspath" -> c.wsPath.ifBlank { "/" }
                "auth" -> if (c.pUser.isNotEmpty()) "Proxy-Authorization: Basic " +
                    Base64.encodeToString("${c.pUser}:${c.pPass}".toByteArray(), Base64.NO_WRAP) else ""
                "rotate" -> arg.split(';').filter { it.isNotEmpty() }.let { if (it.isEmpty()) "" else it[Math.floorMod(rot, it.size)] }
                "random" -> arg.split(';').filter { it.isNotEmpty() }.let { if (it.isEmpty()) "" else it[rnd.nextInt(it.size)] }
                "split" -> "\u0001S\u0001"
                "instant_split", "split_instant" -> "\u0001I\u0001"
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

    // "Soft" sizes only produce a note in the log. Only the HARD limits stop a payload (they protect the phone, and
    // no real payload comes anywhere near them).
    const val MAX_BYTES = 16 * 1024
    const val MAX_PARTS = 32
    const val MAX_PAUSE_MS = 20_000L
    const val HARD_BYTES = 256 * 1024
    const val HARD_PARTS = 1000
    private val requestLine = Regex("^[A-Za-z]+ \\S+ HTTP/\\d(?:\\.\\d)?$")
    private val headerLine = Regex("^([^:\\s]+)[ \\t]*:(.*)$")

    /**
     * Returns why a built payload must not be sent, or null. Every payload a user writes is accepted and sent exactly
     * as written: only an empty payload or an absurd size (far beyond any real payload) is refused.
     */
    fun validate(parts: List<Part>): String? {
        if (parts.isEmpty()) return "the payload is empty"
        if (parts.size > HARD_PARTS) return "too many split parts (${parts.size})"
        if (parts.sumOf { it.data.size } > HARD_BYTES) return "payload is larger than ${HARD_BYTES / 1024} KB"
        return null
    }

    /** Unusual things in a payload. These are only reported in the log, the payload is still sent as typed. */
    fun warnings(parts: List<Part>): List<String> = listOfNotNull(softIssue(parts))

    /** Tags in the payload this app does not know. They are sent as typed. */
    fun unknownTags(payload: String, rot: Int): List<String> =
        tag.findAll(expandChoices(payload, rot)).map { it.groupValues[1] }
            .filter { it.lowercase().replace('-', '_') !in KNOWN_TAGS }.distinct().toList()

    private fun softIssue(parts: List<Part>): String? {
        if (parts.isEmpty()) return "the payload is empty"
        if (parts.size > MAX_PARTS) return "many split parts (${parts.size})"
        val size = parts.sumOf { it.data.size }
        if (size > MAX_BYTES) return "payload is $size bytes, larger than usual"
        if (parts.sumOf { it.pauseMs } > MAX_PAUSE_MS) return "total delay is long (${parts.sumOf { it.pauseMs } / 1000}s)"
        if (parts.any { p -> p.data.any { it == 0.toByte() } }) return "it contains a NUL byte"
        val text = parts.joinToString("") { String(it.data, Charsets.ISO_8859_1) }
        var atStart = true
        var lengths = HashSet<String>()
        var chunked = false
        fun closeRequest(): String? {
            if (lengths.size > 1) return "conflicting Content-Length headers"
            if (lengths.isNotEmpty() && chunked) return "both Content-Length and Transfer-Encoding are set"
            lengths = HashSet(); chunked = false
            return null
        }
        for (raw in text.split("\r\n", "\n")) {
            val line = raw.trimEnd('\r')
            if (line.isEmpty()) { closeRequest()?.let { return it }; atStart = true; continue }
            if (atStart) {
                atStart = false
                if (line.contains(" HTTP/")) {
                    if (!requestLine.matches(line)) return "malformed HTTP request line"
                    continue
                }
                lengths = HashSet(); chunked = false
                continue
            }
            val h = headerLine.find(line) ?: continue
            val name = h.groupValues[1].lowercase()
            val value = h.groupValues[2].trim()
            if (name == "content-length") {
                if (!Regex("\\d{1,19}").matches(value)) return "Content-Length is not a number"
                lengths.add(value.trimStart('0').ifEmpty { "0" })
            } else if (name == "transfer-encoding") chunked = true
        }
        return closeRequest()
    }

    private fun bytes(s: String) = if (s.any { it.code > 255 }) s.toByteArray(Charsets.UTF_8) else s.toByteArray(Charsets.ISO_8859_1)

    /** How many HTTP replies to expect (one per request line in the payload). 0 = not HTTP, do not wait. */
    fun expectedReplies(parts: List<Part>): Int {
        val all = parts.joinToString("") { String(it.data, Charsets.ISO_8859_1) }
        return reqLine.findAll("\n" + all).count()
    }
}

/**
 * Real upstream transport for SSH: direct, HTTP CONNECT/payload, SOCKS4/5, TLS(+SNI)+payload, WebSocket upgrade, direct payload.
 *
 * Normal use (smart rotation): the service hands this class a profile already pinned to ONE combination
 * ([JuanCfg.pinVariant] >= 0) and does the rotating itself, so there is one attempt per combination and the
 * SSH login / TUN / traffic stages can be part of "success". Without a pin it still rotates internally.
 *
 * Every attempt is checked stage by stage: TCP -> (TLS) -> HTTP reply (WebSocket mode needs 101) -> SSH banner.
 */
class JuanProxy(private val c: JuanCfg, private val log: (String) -> Unit, private val protect: (Socket) -> Unit = {}) : Proxy {
    private var sock: Socket? = null
    private var ins: InputStream? = null
    private var outs: OutputStream? = null
    @Volatile private var inflight: Socket? = null
    @Volatile private var cancelled = false
    @Volatile private var wsWas2xx = false

    private companion object {
        val rotation = AtomicInteger()
        /** "sni|host" pairs whose certificate cannot match (borrowed SNI); later attempts skip the failing strict handshakes. */
        val relaxedFronts: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
    }

    private fun isCertProblem(e: Throwable): Boolean = generateSequence(e) { it.cause }.take(6).any {
        it is SSLPeerUnverifiedException || it is java.security.cert.CertificateException ||
            it is java.security.cert.CertPathValidatorException || it.message?.contains("does not match", true) == true
    }

    /** Called when the user disconnects: aborts a handshake that is still in progress. */
    fun cancel() {
        cancelled = true
        try { inflight?.close() } catch (_: Exception) {}
        try { sock?.close() } catch (_: Exception) {}
    }

    private fun checkCancelled() {
        if (cancelled || Thread.currentThread().isInterrupted) throw JuanConnException(JuanFail.CANCELLED, "Cancelled by user")
    }

    /**
     * Pinned (smart rotation): exactly one attempt. Unpinned: every connection starts at the next proxy / SNI /
     * payload and falls through to the next combination (up to 30 tries) before giving up.
     */
    override fun connect(sf: SocketFactory?, host: String, port: Int, timeout: Int) {
        val pinned = c.pinVariant >= 0
        val pxs: List<ProxyEntry?> = if (c.from == "direct" || c.proxies.isEmpty()) listOf(null) else c.proxies
        val snis = c.snis.ifEmpty { listOf(c.sni) }
        val pays = c.payloads.ifEmpty { listOf(c.payload) }
        // every option of a [rotate=..]/[random=..] tag is its own candidate payload
        val cands = ArrayList<Pair<String, Int>>()
        if (pinned) cands.add((pays.firstOrNull() ?: c.payload) to c.pinVariant)
        else for (p in pays) for (v in 0 until JuanPayload.variantCount(p)) cands.add(p to v)
        val total = pxs.size * snis.size * cands.size
        val start = if (pinned) 0 else rotation.getAndIncrement()
        val tries = minOf(total, 30)
        val to = when { pinned -> minOf(timeout, 10_000); tries > 1 -> minOf(timeout, 7_000); else -> timeout }
        var last: Exception? = null
        for (n in 0 until tries) {
            val idx = Math.floorMod(start + n, total)
            val pi = idx % cands.size
            val si = (idx / cands.size) % snis.size
            val xi = idx / (cands.size * snis.size)
            try { attempt(host, port, to, pxs[xi], snis[si], cands[pi].first, cands[pi].second); return }
            catch (e: InterruptedException) { throw e }
            catch (e: Exception) {
                last = e
                if (tries == 1 || cancelled) throw e
                log("Retrying...")
            }
        }
        rotation.addAndGet(tries - 1)        // next connect continues after the ones already tried
        throw last ?: IOException("No connection candidate")
    }

    private fun attempt(host: String, port: Int, timeout: Int, px: ProxyEntry?, sniName: String, payload: String, rot: Int) {
        checkCancelled()
        wsWas2xx = false
        val viaProxy = c.from != "direct" && px != null
        val th = if (viaProxy) px!!.host else host
        val tp = if (viaProxy) px!!.port else port
        val pUser = px?.user ?: c.pUser
        val pPass = px?.pass ?: c.pPass
        log("DNS: resolving $th")
        val addr = try { InetAddress.getByName(th) } catch (e: UnknownHostException) {
            log("DNS: FAILED ($th)")
            throw JuanConnException(JuanFail.DNS, "Cannot resolve host: $th", e)
        }
        log("DNS: $th -> ${addr.hostAddress}")
        var s = Socket()
        inflight = s
        protect(s)
        try {
            try { s.connect(InetSocketAddress(addr, tp), timeout) }
            catch (e: SocketTimeoutException) {
                log("TCP: TIMEOUT ($th:$tp)")
                throw JuanConnException(JuanFail.TCP_TIMEOUT, "Connection timed out: $th:$tp", e)
            } catch (e: java.net.ConnectException) {
                if (e.message?.contains("refused", true) == true) {
                    log("TCP: REFUSED ($th:$tp)")
                    throw JuanConnException(JuanFail.TCP_REFUSED, "Connection refused: $th:$tp", e)
                }
                throw e
            }
            checkCancelled()
            s.soTimeout = timeout
            s.tcpNoDelay = true
            log("TCP: CONNECTED ${addr.hostAddress}:$tp (${c.from})")
            if (c.from == "tls" || c.from == "sni" || (c.from == "ws" && sniName.isNotBlank())) {
                val name = sniName.ifBlank { th }
                if (name.matches(Regex("[0-9.:]+"))) log("TLS: warning - SNI is an IP address; servers usually need a domain name here")
                log("TLS: handshake, SNI=$name")
                // A borrowed SNI (front/bug domain) can never match the real server's certificate. Hybrid handling:
                // strict check -> check against the real SSH server name -> continue unverified; the SSH host key
                // (trust prompt / pinned fingerprint) then stays the identity check. A SNI that IS the server's own
                // name is never downgraded, so a bad certificate there still fails.
                val front = !name.equals(host, true) && !name.equals(th, true)
                val frontKey = "${name.lowercase()}|${host.lowercase()}"
                fun reopen(): Socket {
                    try { s.close() } catch (_: Exception) {}
                    val n = Socket(); inflight = n; protect(n)
                    n.connect(InetSocketAddress(addr, tp), timeout); n.soTimeout = timeout; n.tcpNoDelay = true
                    return n
                }
                fun wrap(verify: Boolean, verifyAs: String? = null): SSLSocket = try { tlsWrap(s, name, tp, verify, verifyAs) }
                    catch (e: javax.net.ssl.SSLException) { throw if (verify && front && isCertProblem(e)) CertMismatch(e) else e }
                val ssl: SSLSocket = try {
                    if (!c.verify) { log("TLS: warning - certificate verification is OFF"); wrap(false) }
                    else if (front && frontKey in relaxedFronts) {
                        log("TLS: borrowed SNI, certificate not verified (SSH host key is checked next)")
                        wrap(false)
                    } else try { wrap(true) } catch (e: CertMismatch) {
                        if (!front) throw e.real
                        log("TLS: certificate is not for the borrowed SNI '$name' (normal for SNI fronting), checking '$host' instead")
                        s = reopen()
                        try { wrap(true, host) } catch (e2: CertMismatch) {
                            log("TLS: certificate not verifiable, continuing; the SSH host key is the identity check")
                            relaxedFronts.add(frontKey)
                            s = reopen()
                            wrap(false)
                        }
                    }
                } catch (e: javax.net.ssl.SSLException) {
                    val r = if (e is CertMismatch) e.real else e
                    log("TLS: FAILED")
                    throw JuanConnException(JuanFail.TLS, "TLS failed: ${r.message}", r)
                }
                log("TLS: ${ssl.session.protocol} ${ssl.session.cipherSuite}" + if (c.verify && frontKey !in relaxedFronts) ", certificate verified" else ", certificate not verified")
                s = ssl
                inflight = s
            }
            checkCancelled()
            val i = PushbackInputStream(s.getInputStream(), 512)
            val o = s.getOutputStream()
            val ws = c.from == "ws"
            val custom = payload.isNotBlank() && (c.custom || c.from == "dpay")
            when (c.from) {
                "http" -> {
                    if (custom) sendPayload(o, i, payload, sniName, host, port, rot)
                    else {
                        val auth = if (pUser.isNotEmpty()) "Proxy-Authorization: Basic " +
                            Base64.encodeToString("$pUser:$pPass".toByteArray(), Base64.NO_WRAP) + "\r\n" else ""
                        o.write("CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\nProxy-Connection: keep-alive\r\n$auth\r\n".toByteArray(Charsets.ISO_8859_1)); o.flush()
                        awaitTunnel(i, 1, false)
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
                        awaitTunnel(i, 1, ws, key)
                    }
                }
            }
            // The tunnel only counts as open once the SSH server itself has answered with its banner.
            verifyBanner(i, s)
            s.soTimeout = 0
            sock = s; ins = i; outs = o
        } catch (e: Exception) {
            try { s.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun sendPayload(o: OutputStream, i: PushbackInputStream, payload: String, sni: String, host: String, port: Int, rot: Int) {
        val parts = JuanPayload.build(c, payload, sni, host, port, rot)
        JuanPayload.validate(parts)?.let {
            log("Payload: REJECTED - $it")
            throw JuanConnException(JuanFail.BAD_PAYLOAD, "Payload rejected: $it")
        }
        JuanPayload.warnings(parts).forEach { log("Payload: note - $it (sent as typed)") }
        JuanPayload.unknownTags(payload, rot).forEach { log("Payload: tag [$it] is not known here and is sent as typed") }
        for ((n, p) in parts.withIndex()) {
            checkCancelled()
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
        awaitTunnel(i, expect, c.from == "ws")
    }

    /**
     * Reads replies until the tunnel is open. Replies to earlier (decoy) requests are skipped.
     * WebSocket mode needs 101 (an HTTP 200 is only tolerated when the SSH banner follows, see [verifyBanner]);
     * other HTTP modes accept 101 or a 2xx to the last request (a CONNECT 200 is the normal success there).
     * 3xx / 4xx / 5xx are rejections with their own failure kind.
     */
    private fun awaitTunnel(i: PushbackInputStream, expected: Int, ws: Boolean, key: String? = null) {
        val proto = if (ws) "WebSocket" else "HTTP"
        var left = expected
        var saw2xx = false
        while (true) {
            checkCancelled()
            val head = try { readHead(i, ws) } catch (e: SocketTimeoutException) {
                if (saw2xx) { log("Proxy: no further reply, continuing"); return }
                log("$proto: NO REPLY (timeout)")
                throw JuanConnException(JuanFail.PROXY_TIMEOUT, "The proxy did not answer the handshake in time", e)
            }
            if (head == null) { log("$proto: no HTTP reply, SSH banner arrived first"); return }
            val first = head.substringBefore("\n").trim()
            val code = first.split(" ").getOrNull(1)?.toIntOrNull()
            left--
            when {
                code == 101 -> {
                    if (ws) log("WebSocket: 101 SWITCHING PROTOCOLS") else log("HTTP: $first")
                    if (ws && key != null) checkAccept(head, key)
                    return
                }
                code != null && code in 200..299 && left <= 0 -> {
                    if (ws) { wsWas2xx = true; log("WebSocket: HTTP $code received, expected 101") } else log("HTTP: $first")
                    return
                }
                code != null && code in 200..299 -> {
                    saw2xx = true; if (ws) wsWas2xx = true
                    log("Proxy: skipping reply to earlier request ($first)"); skipBody(i, head)
                }
                left > 0 -> { log("Proxy: skipping reply to earlier request ($first)"); skipBody(i, head) }
                else -> {
                    log("$proto: REJECTED ($first)")
                    val kind = when {
                        code == null -> JuanFail.BAD_REPLY
                        code in 300..399 -> JuanFail.HTTP_REDIRECT
                        code in 500..599 -> JuanFail.HTTP_SERVER
                        else -> JuanFail.HTTP_REJECT
                    }
                    throw JuanConnException(kind, "Proxy replied: $first")
                }
            }
        }
    }

    /** Built-in WebSocket request only (we know the key): a present-but-wrong Sec-WebSocket-Accept is not a real upgrade. */
    private fun checkAccept(head: String, key: String) {
        val got = Regex("(?im)^sec-websocket-accept:[ \\t]*(\\S+)").find(head)?.groupValues?.get(1) ?: return
        val want = Base64.encodeToString(
            java.security.MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray()), Base64.NO_WRAP)
        if (got != want) {
            log("WebSocket: REJECTED (bad Sec-WebSocket-Accept)")
            throw JuanConnException(JuanFail.BAD_WS, "Invalid WebSocket handshake: Sec-WebSocket-Accept does not match")
        }
    }

    /**
     * Looks for the SSH server's own identification line and puts it back for JSch to read.
     * Waits only a short time: some WebSocket/HTTP bridges send the banner only after the client has sent its own,
     * so silence is not failure yet - JSch then sends its identification and the SSH login decides. Wrong data
     * instead of a banner, a closed connection, or (WebSocket mode) an HTTP 200 with no banner are failures.
     */
    private fun verifyBanner(i: PushbackInputStream, s: Socket) {
        val old = s.soTimeout
        val bannerWait = if (c.sshHost == "127.0.0.1") 20_000 else 4_000   // a DNS tunnel answers slowly
        s.soTimeout = if (old > 0) minOf(old, bannerWait) else bannerWait
        val buf = ByteArray(255)
        var n = 0
        try {
            while (n < buf.size) {
                checkCancelled()
                val b = i.read()
                if (b < 0) {
                    log("SSH: BANNER NOT RECEIVED (connection closed)")
                    throw JuanConnException(JuanFail.PROXY_CLOSED, "Proxy closed the connection before the SSH banner")
                }
                buf[n++] = b.toByte()
                if (n == 4 && String(buf, 0, 4, Charsets.ISO_8859_1) != "SSH-") {
                    if (wsWas2xx) {
                        log("WebSocket: REJECTED (HTTP 200 is not an upgrade, no SSH banner)")
                        throw JuanConnException(JuanFail.BAD_WS, "Invalid WebSocket handshake: the proxy answered 200 instead of 101 and no SSH banner followed")
                    }
                    log("SSH: BANNER NOT RECEIVED (server sent other data)")
                    throw JuanConnException(JuanFail.SSH_BANNER, "No SSH banner: the server sent something else")
                }
                if (b == 10) break
            }
        } catch (e: SocketTimeoutException) {
            if (n > 0) i.unread(buf, 0, n)
            if (wsWas2xx) {
                log("WebSocket: REJECTED (HTTP 200 is not an upgrade, no SSH banner)")
                throw JuanConnException(JuanFail.BAD_WS, "Invalid WebSocket handshake: the proxy answered 200 instead of 101 and no SSH banner followed", e)
            }
            s.soTimeout = old
            log("SSH: no banner yet, sending our identification first")
            return
        }
        s.soTimeout = old
        i.unread(buf, 0, n)
        log("SSH: BANNER RECEIVED (" + String(buf, 0, n, Charsets.ISO_8859_1).trim().filter { it.code in 32..126 }.take(60) + ")")
    }

    /** Returns the reply head, or null when the server started with an SSH banner (bytes are pushed back). */
    private fun readHead(i: PushbackInputStream, ws: Boolean): String? {
        val sb = StringBuilder()
        while (sb.length < 16384) {
            checkCancelled()
            val b = i.read()
            if (b < 0) {
                log("Proxy: CLOSED during handshake")
                throw JuanConnException(JuanFail.PROXY_CLOSED, "Proxy closed the connection during handshake")
            }
            if (sb.isEmpty() && (b == 13 || b == 10)) continue            // stray blank lines before a reply
            sb.append(b.toChar())
            if (sb.length == 4 && sb.toString() == "SSH-") { i.unread("SSH-".toByteArray()); return null }
            if (sb.length == 5 && !sb.startsWith("HTTP/")) {
                log((if (ws) "WebSocket" else "HTTP") + ": REJECTED (reply is not HTTP)")
                throw JuanConnException(if (ws) JuanFail.BAD_WS else JuanFail.BAD_REPLY,
                    "Unexpected reply from the proxy (not HTTP): " + sb.toString().filter { it.code in 32..126 })
            }
            if (sb.endsWith("\r\n\r\n") || sb.endsWith("\n\n")) return sb.toString()
        }
        throw JuanConnException(JuanFail.BAD_REPLY, "Proxy response too large")
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
