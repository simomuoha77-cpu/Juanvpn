package com.juanvpn.app

import android.net.Uri
import android.util.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONObject
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection

/**
 * Cloud sharing for .HJ configs, in the style of "Save to cloud" in other injector apps.
 *
 *  - The config is encrypted on the phone with a key derived from the 8-character cloud key.
 *  - The server only ever sees a lookup token (SHA-256 of the key) and ciphertext.
 *  - Modes: normal, burn (deleted on first import), expiry (deleted after a date).
 *
 * The server is your own deployment of cloud-server/ (Cloudflare Worker + D1).
 */
object JuanCloud {
    private const val ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    private const val EMOJI_BASE = 0x1F600          // 64 consecutive emoticons: U+1F600..U+1F63F
    private const val KDF_ITER = 100_000
    private const val AAD = "JUAN-CLOUD|1"
    private val rnd = SecureRandom()
    private const val CODE_PREFIX = "JUAN1:"

    /**
     * Optional: put your cloud server here (for example "https://juan-cloud.yourname.workers.dev") and rebuild.
     * Then every user of your app can import cloud keys without setting a server in Settings.
     */
    const val DEFAULT_SERVER = "https://juanvpn.juanvpn.workers.dev"

    /** Offline config code: the whole (already locked or unlocked) .HJ text, compressed. No server involved. */
    fun encodeCode(text: String): String {
        val d = java.util.zip.Deflater(9, true)
        d.setInput(text.toByteArray(Charsets.UTF_8)); d.finish()
        val out = java.io.ByteArrayOutputStream(); val buf = ByteArray(4096)
        while (!d.finished()) out.write(buf, 0, d.deflate(buf))
        d.end()
        return CODE_PREFIX + Base64.encodeToString(out.toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun decodeCode(code: String): String {
        val body = code.trim().substring(CODE_PREFIX.length).filter { !it.isWhitespace() }
        val bytes = try { Base64.decode(body, Base64.URL_SAFE) } catch (_: Exception) { throw IllegalArgumentException("That config code is damaged") }
        val inf = java.util.zip.Inflater(true)
        inf.setInput(bytes)
        val out = java.io.ByteArrayOutputStream(); val buf = ByteArray(4096)
        try {
            while (!inf.finished()) {
                val n = inf.inflate(buf)
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break
                out.write(buf, 0, n)
                require(out.size() <= 2_000_000) { "Config code is too large" }
            }
        } catch (e: java.util.zip.DataFormatException) { throw IllegalArgumentException("That config code is damaged") }
        finally { inf.end() }
        require(out.size() > 0) { "That config code is damaged" }
        return out.toString("UTF-8")
    }

    fun newKey(): String = (1..8).map { ALPHA[rnd.nextInt(ALPHA.length)] }.joinToString("")

    /* ---------------------------------------------------------------- emoji key */

    private fun checks(idx: List<Int>): Pair<Int, Int> {
        val c1 = (idx.sum() * 7 + 3) % 64
        var c2 = 5
        idx.forEachIndexed { i, v -> c2 = (c2 + v * (i + 3)) % 64 }
        return c1 to c2
    }

    /** 8 key characters + 2 check emoji, so a mistyped emoji key is rejected instead of fetching nothing. */
    fun emoji(key: String): String {
        val idx = key.map { ALPHA.indexOf(it) }
        val (c1, c2) = checks(idx)
        return (idx + c1 + c2).joinToString("") { String(Character.toChars(EMOJI_BASE + it)) }
    }

    private fun fromEmoji(s: String): String? {
        val vals = ArrayList<Int>()
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            if (cp in EMOJI_BASE until EMOJI_BASE + 64) vals.add(cp - EMOJI_BASE)
        }
        if (vals.size != 10) return null
        val idx = vals.take(8)
        if (idx.any { it >= ALPHA.length }) return null
        val (c1, c2) = checks(idx)
        if (vals[8] != c1 || vals[9] != c2) throw IllegalArgumentException("Emoji key has a mistake. Copy it again.")
        return idx.map { ALPHA[it] }.joinToString("")
    }

    /* ---------------------------------------------------------------- input parsing */

    class Ref(val server: String?, val key: String)

    /** Accepts https://server/KEY, juanvpn://import?key=KEY&server=..., a bare key, or an emoji key. */
    fun parse(input: String): Ref {
        val t = input.trim()
        require(t.isNotEmpty()) { "Enter a cloud link, key or emoji key" }
        if (t.startsWith("juanvpn://", true)) {
            val u = Uri.parse(t)
            val key = u.getQueryParameter("key").orEmpty()
            validKey(key)
            return Ref(u.getQueryParameter("server")?.let { base(it) }, key)
        }
        if (t.startsWith("https://", true) || t.startsWith("http://", true)) {
            require(t.startsWith("https://", true)) { "Cloud links must use https" }
            val u = Uri.parse(t)
            val key = u.pathSegments.lastOrNull().orEmpty()
            validKey(key)
            return Ref("https://" + u.encodedAuthority.orEmpty(), key)
        }
        fromEmoji(t)?.let { return Ref(null, it) }
        val k = t.filter { !it.isWhitespace() }
        validKey(k)
        return Ref(null, k)
    }

    private fun validKey(k: String) {
        require(k.length == 8 && k.all { it in ALPHA }) { "That is not a valid cloud key (8 letters and numbers)" }
    }

    /** Reduces whatever the user typed to https://host[:port]. */
    fun base(raw: String): String {
        val t = raw.trim().trimEnd('/')
        require(t.isNotEmpty()) { "Set your cloud server in Settings first" }
        val u = URL(if (t.contains("://")) t else "https://$t")
        require(u.protocol == "https") { "The cloud server must use https" }
        return "https://" + u.authority
    }

    /* ---------------------------------------------------------------- crypto */

    private fun derive(key: String): SecretKeySpec {
        val spec = PBEKeySpec(key.toCharArray(), "juancloud-v1|enc".toByteArray(), KDF_ITER, 256)
        val bytes = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", BouncyCastleProvider()).generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(bytes, "AES")
    }

    private fun token(key: String): String =
        MessageDigest.getInstance("SHA-256").digest(("juancloud-lookup|$key").toByteArray())
            .joinToString("") { "%02x".format(it) }

    private fun encrypt(plain: String, key: String): String {
        val iv = ByteArray(12).also(rnd::nextBytes)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, derive(key), GCMParameterSpec(128, iv))
        c.updateAAD(AAD.toByteArray())
        return Base64.encodeToString(iv + c.doFinal(plain.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }

    private fun decrypt(data: String, key: String): String {
        val raw = Base64.decode(data, Base64.NO_WRAP)
        require(raw.size > 28) { "The cloud data is damaged" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, derive(key), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
        c.updateAAD(AAD.toByteArray())
        return String(c.doFinal(raw, 12, raw.size - 12), Charsets.UTF_8)
    }

    /* ---------------------------------------------------------------- network */

    private fun http(method: String, url: String, body: String?): Pair<Int, String> {
        require(url.startsWith("https://")) { "The cloud server must use https" }
        val c = URL(url).openConnection() as HttpsURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 15_000; c.readTimeout = 25_000
            c.setRequestProperty("User-Agent", "JUAN-VPN")
            c.setRequestProperty("Accept", "application/json")
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = c.responseCode
            val stream = if (code >= 400) c.errorStream else c.inputStream
            val text = stream?.use { s ->
                val out = java.io.ByteArrayOutputStream(); val buf = ByteArray(8192); var total = 0
                while (true) { val n = s.read(buf); if (n < 0) break; total += n; require(total <= 1_500_000) { "Server reply is too large" }; out.write(buf, 0, n) }
                out.toString("UTF-8")
            }.orEmpty()
            return code to text
        } finally { c.disconnect() }
    }

    private fun errorOf(code: Int, body: String): String {
        val msg = try { JSONObject(body).optString("error") } catch (_: Exception) { "" }
        return msg.ifBlank { "Server replied HTTP $code" }
    }

    fun ping(server: String): String {
        val (code, body) = http("GET", base(server) + "/api/health", null)
        if (code != 200) throw IllegalStateException("Server replied HTTP $code. Is this your JUAN cloud server?")
        val j = try { JSONObject(body) } catch (_: Exception) { throw IllegalStateException("This URL is not a JUAN cloud server") }
        if (j.optString("service") != "juan-cloud") throw IllegalStateException("This URL is not a JUAN cloud server")
        return "Cloud server is working"
    }

    /** Uploads the encrypted config. mode: normal | burn | expiry (expiresSec = unix seconds). */
    fun upload(serverRaw: String, hjText: String, mode: String, expiresSec: Long): String {
        require(mode == "normal" || mode == "burn" || mode == "expiry") { "Unknown cloud mode" }
        val server = base(serverRaw.ifBlank { DEFAULT_SERVER })
        require(hjText.length <= 200_000) { "Config is too large to upload" }
        var lastErr = "Upload failed"
        repeat(3) {
            val key = newKey()
            val j = JSONObject().put("token", token(key)).put("data", encrypt(hjText, key)).put("mode", mode)
            if (mode == "expiry") j.put("expires", expiresSec)
            val (code, body) = http("POST", "$server/api/put", j.toString())
            if (code in 200..299) {
                return JSONObject()
                    .put("key", key).put("emoji", emoji(key))
                    .toString()
            }
            if (code != 409) throw IllegalStateException(errorOf(code, body))
            lastErr = "Could not find a free key, try again"
        }
        throw IllegalStateException(lastErr)
    }

    /** Downloads and decrypts a config. defaultServer is used when the input has no server in it. */
    fun fetch(defaultServer: String, input: String): String {
        if (input.trim().startsWith(CODE_PREFIX, true)) return decodeCode(input)   // offline code, no server
        val ref = parse(input)
        val server = ref.server ?: base(defaultServer.ifBlank { DEFAULT_SERVER })
        val (code, body) = http("GET", "$server/api/get/" + token(ref.key), null)
        if (code == 404) throw IllegalStateException("Config not found. It may have expired or was already burned (one-time).")
        if (code !in 200..299) throw IllegalStateException(errorOf(code, body))
        val data = JSONObject(body).optString("data")
        require(data.isNotEmpty()) { "The server returned no data" }
        try { return decrypt(data, ref.key) }
        catch (e: java.security.GeneralSecurityException) { throw IllegalStateException("Wrong key or damaged data") }
    }
}
