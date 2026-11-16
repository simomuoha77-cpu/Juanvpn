package com.juanvpn.app

import android.content.Context
import org.json.JSONObject
import java.io.IOException
import java.net.UnknownHostException
import java.security.MessageDigest

/** Why a connection attempt failed, so the log and the rotation logic can tell the cases apart. */
enum class JuanFail(val label: String, val rotates: Boolean = true) {
    DNS("DNS resolution failure"),
    NETWORK("Network unreachable"),
    TCP_TIMEOUT("TCP connection timeout"),
    TCP_REFUSED("TCP connection refused"),
    TLS("TLS handshake failure"),
    HTTP_REDIRECT("HTTP 301/302 redirect"),
    HTTP_REJECT("HTTP 400/403 rejection"),
    HTTP_SERVER("HTTP 5xx server error"),
    BAD_WS("Invalid WebSocket handshake"),
    BAD_REPLY("Invalid proxy reply"),
    PROXY_TIMEOUT("Proxy handshake timeout"),
    PROXY_CLOSED("Proxy connection closed"),
    BAD_PAYLOAD("Payload rejected"),
    SSH_BANNER("SSH banner not received"),
    SSH_TIMEOUT("SSH server timeout"),
    SSH_AUTH("SSH authentication failure", false),
    SSH_OTHER("SSH error"),
    TUN_INIT("TUN initialization failure"),
    TRAFFIC("Traffic check failure"),
    CANCELLED("Cancelled", false),
    OTHER("Connection error")
}

/** A failure raised by our own transport code. [kind] is exact; no message parsing needed. */
class JuanConnException(val kind: JuanFail, message: String, cause: Throwable? = null) : IOException(message, cause)

/** Rotation cannot help (missing VPN permission, nothing usable to try...). The message is shown as written. */
class JuanFatalException(message: String) : RuntimeException(message)

/**
 * Smart rotation: builds every proxy x SNI x payload combination from the profile, puts the last
 * successful one first, and remembers the winner. Nothing here edits the user's profile, and no
 * passwords (SSH or proxy) are ever written to the rotation history.
 */
object JuanRotation {
    private const val PREFS = "juan_rotation"
    private const val MAX_COMBOS = 120

    class Combo(
        val no: Int,                 // 1-based position in the profile's own order
        val px: ProxyEntry?,
        val sni: String,
        val payload: String,
        val payloadNo: Int,          // 1-based payload number in the profile
        val variant: Int,            // which [rotate=..]/[random=..] option
        val usesPayload: Boolean,
        val id: String
    ) {
        val proxyLabel: String get() = px?.let { "${it.host}:${it.port}" } ?: "direct"
    }

    class Plan(val combos: List<Combo>, val skipped: List<String>)

    private fun sha(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }

    private fun idOf(c: JuanCfg, px: ProxyEntry?, sni: String, payload: String, variant: Int, uses: Boolean): String =
        sha(listOf(c.from, px?.host ?: "", px?.port ?: 0, sni, if (uses) sha(payload) else "", variant, c.sshHost, c.sshPort)
            .joinToString("|")).take(16)

    /** Same ordering the old per-connection rotation used: proxy, then SNI, then payload. */
    fun plan(c: JuanCfg): Plan {
        val pxs: List<ProxyEntry?> = if (c.from == "direct" || c.proxies.isEmpty()) listOf(null) else c.proxies
        val snis = c.snis.ifEmpty { listOf(c.sni) }
        val pays = c.payloads.ifEmpty { listOf(c.payload) }
        val all = ArrayList<Combo>()
        for (px in pxs) {
            for (sni in snis) {
                for ((pn, p) in pays.withIndex()) {
                    val uses = p.isNotBlank() && (c.custom || c.from == "dpay")
                    for (v in 0 until JuanPayload.variantCount(p)) {
                        all.add(Combo(all.size + 1, px, sni, p, pn + 1, v, uses, idOf(c, px, sni, p, v, uses)))
                    }
                }
            }
        }
        val ok = ArrayList<Combo>()
        val skipped = ArrayList<String>()
        for (k in all.take(MAX_COMBOS)) {
            if (k.usesPayload) {
                val why = try {
                    JuanPayload.validate(JuanPayload.build(pin(c, k), k.payload, k.sni, c.sshHost, c.sshPort, k.variant))
                } catch (e: Exception) { "payload could not be processed (${e.message})" }
                if (why != null) {
                    skipped.add("Combination ${k.no} skipped (${k.proxyLabel}): payload rejected - $why")
                    continue
                }
            }
            ok.add(k)
        }
        if (all.size > MAX_COMBOS) skipped.add("Rotation limited to the first $MAX_COMBOS of ${all.size} combinations")
        return Plan(ok, skipped)
    }

    /** A copy of the profile locked to one combination. The profile the user saved is never touched. */
    fun pin(c: JuanCfg, k: Combo): JuanCfg = c.copy(
        pHost = k.px?.host ?: c.pHost, pPort = k.px?.port ?: c.pPort,
        pUser = k.px?.user ?: c.pUser, pPass = k.px?.pass ?: c.pPass,
        sni = k.sni, proxies = listOfNotNull(k.px), snis = listOf(k.sni),
        payload = k.payload, payloads = listOf(k.payload), pinVariant = k.variant
    )

    /** Preferred combination first, the rest in profile order. Returns the list and the preferred one's number (0 = none). */
    fun order(combos: List<Combo>, preferredId: String?): Pair<List<Combo>, Int> {
        val i = if (preferredId == null) -1 else combos.indexOfFirst { it.id == preferredId }
        if (i < 0) return combos to 0
        return (listOf(combos[i]) + combos.filterIndexed { idx, _ -> idx != i }) to combos[i].no
    }

    // ---- remembered winner (no passwords, no proxy credentials) ----

    private fun scope(c: JuanCfg): String =
        sha(listOf(c.name, c.from, c.sshHost, c.sshPort, c.tunnel).joinToString("|")).take(16)

    fun loadPreferred(ctx: Context, c: JuanCfg): String? = try {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("pref_" + scope(c), null)
            ?.let { JSONObject(it).optString("id") }?.ifBlank { null }
    } catch (_: Exception) { null }

    fun savePreferred(ctx: Context, c: JuanCfg, k: Combo) {
        try {
            val o = JSONObject()
                .put("id", k.id)
                .put("proxy", k.proxyLabel)
                .put("mode", c.from)
                .put("sni", k.sni)
                .put("payloadNo", if (k.usesPayload) k.payloadNo else 0)
                .put("payloadVariant", k.variant)
                .put("payloadRef", if (k.usesPayload) sha(k.payload).take(12) else "")
                .put("sshServer", "${c.sshHost}:${c.sshPort}")
                .put("lastSuccess", System.currentTimeMillis())
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("pref_" + scope(c), o.toString()).apply()
        } catch (_: Exception) {}
    }

    // ---- failure classification ----

    private fun chain(t: Throwable): List<Throwable> = generateSequence(t) { it.cause }.take(8).toList()

    /** The exception that best explains the failure (ours if there is one, else JSch's cause). */
    fun rootCause(t: Throwable): Throwable = chain(t).firstOrNull { it is JuanConnException } ?: (t.cause ?: t)

    fun classify(t: Throwable): JuanFail {
        val ch = chain(t)
        ch.firstOrNull { it is JuanConnException }?.let { return (it as JuanConnException).kind }
        if (ch.any { it is InterruptedException }) return JuanFail.CANCELLED
        if (ch.any { it is UnknownHostException }) return JuanFail.DNS
        val m = ch.mapNotNull { it.message }.joinToString(" | ").lowercase()
        return when {
            m.contains("auth fail") || m.contains("auth cancel") || m.contains("userauth") -> JuanFail.SSH_AUTH
            m.contains("algorithm negotiation") || m.contains("hostkey") || m.contains("host key") -> JuanFail.SSH_OTHER
            m.contains("unreachable") || m.contains("enetunreach") -> JuanFail.NETWORK
            m.contains("refused") -> JuanFail.TCP_REFUSED
            m.contains("timeout") || m.contains("timed out") -> JuanFail.SSH_TIMEOUT
            m.contains("reset") || m.contains("closed") || m.contains("end of io stream") || m.contains("broken pipe") -> JuanFail.PROXY_CLOSED
            else -> JuanFail.OTHER
        }
    }

    /** True when trying the next combination could help. Bad credentials, host-key problems, fatal setup errors: no. */
    fun shouldRotate(t: Throwable): Boolean {
        if (chain(t).any { it is JuanFatalException }) return false
        return classify(t).rotates && JuanSshEngine.transient(t)
    }
}
