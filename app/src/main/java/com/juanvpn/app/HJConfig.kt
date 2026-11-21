package com.juanvpn.app

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * JUAN HJ containers.
 *
 *  - HJ01 (new, binary, see HJ01.java): envelope encryption, Argon2id, HKDF, per-file random data key,
 *    password and/or device/recipient key slots. Every new locked export uses this. It is stored as the text
 *    "HJ01." + base64url so the existing export/share/cloud/config-code paths keep working unchanged.
 *  - Legacy JSON containers (versions 1 and 2, PBKDF2 + AES-GCM): IMPORT ONLY. Nothing new is ever written in
 *    those formats, and they are never used to open or weaken an HJ01 file.
 */
object HJConfig {
    private const val FORMAT = "JUAN-HJ"
    private const val VERSION = 2
    private const val LEGACY_VERSION = 1
    private const val ITERATIONS = 310_000
    private const val LEGACY_AAD = "JUAN-HJ|1"
    private val random = SecureRandom()
    private val encryptedFields = arrayOf("kdf", "iterations", "salt", "iv", "ciphertext")

    fun unlocked(configJson: String): String {
        val config = JSONObject(configJson)
        return JSONObject().put("format", FORMAT).put("version", VERSION)
            .put("locked", false).put("config", config).toString(2)
    }

    fun isHJ01(text: String): Boolean = text.trimStart().startsWith(HJ01.PREFIX)

    /**
     * Files exported without a password. Every byte is random-looking (no header, no readable text, a fresh salt per
     * file, random padding), so no other app or tool can show or parse anything. JUAN VPN opens them without a prompt.
     * The older "HJO1." form is still accepted on import.
     */
    private const val OPEN_PREFIX = "HJO1."
    private const val OPEN_AAD = "JUAN-HJ-OPEN|1"
    private val sealedText = Regex("^[A-Za-z0-9_-]{60,}$")
    private val sA = byteArrayOf(18, 16, -124, 97, -104, -5, -118, 78, -94, 109, 38, -5, -49, 47, 71, 124, 89, -121, 86, -16, -91, -49, 67, -45, -125, -31, -23, 111, 47, 10, -73, -4)
    private val sB = byteArrayOf(5, -101, -11, -115, 2, -66, -71, 55, -17, -121, -56, -108, -42, -12, -99, 25, -26, 64, 39, -5, 99, 114, -78, -91, -56, 91, 38, 58, 42, -114, -98, 95)

    fun isOpen(text: String): Boolean {
        val t = text.trim()
        return t.startsWith(OPEN_PREFIX) || sealedText.matches(t)
    }

    private fun legacyOpenKey(): SecretKeySpec = SecretKeySpec(
        java.security.MessageDigest.getInstance("SHA-256").digest("JUAN-HJ-OPEN-KEY|v1|7c1f0d9a-5b3e-4e8a-9d52-juanvpn-hj".toByteArray()), "AES")

    private fun sealKey(salt: ByteArray): SecretKeySpec {
        val seed = ByteArray(32) { (sA[it].toInt() xor sB[it].toInt()).toByte() }
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(seed, "HmacSHA256"))
        seed.fill(0)
        return SecretKeySpec(mac.doFinal(salt + byteArrayOf(0x4a, 0x48, 0x01)), "AES")
    }

    fun sealOpen(configJson: String): String {
        val json = JSONObject(configJson).toString().toByteArray(Charsets.UTF_8)
        val pad = random.nextInt(64)
        val plain = ByteArray(4 + json.size + pad)
        plain[0] = (json.size ushr 24).toByte(); plain[1] = (json.size ushr 16).toByte()
        plain[2] = (json.size ushr 8).toByte(); plain[3] = json.size.toByte()
        System.arraycopy(json, 0, plain, 4, json.size)
        if (pad > 0) { val padBytes = ByteArray(pad); random.nextBytes(padBytes); System.arraycopy(padBytes, 0, plain, 4 + json.size, pad) }
        try {
            val salt = ByteArray(16).also { random.nextBytes(it) }
            val iv = ByteArray(12).also { random.nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, sealKey(salt), GCMParameterSpec(128, iv))
            c.updateAAD(salt)
            return Base64.encodeToString(salt + iv + c.doFinal(plain), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } finally { plain.fill(0); json.fill(0) }
    }

    fun openOpen(text: String): String {
        val t = text.trim()
        val legacy = t.startsWith(OPEN_PREFIX)
        val raw = try { Base64.decode(t.removePrefix(OPEN_PREFIX).filter { !it.isWhitespace() }, Base64.URL_SAFE) }
            catch (_: IllegalArgumentException) { throw IllegalArgumentException("This config file is damaged") }
        val bad = IllegalArgumentException("This config file is damaged or not a JUAN VPN config")
        if (legacy) {
            if (raw.size <= 28) throw bad
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, legacyOpenKey(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
            c.updateAAD(OPEN_AAD.toByteArray())
            val plain = try { c.doFinal(raw, 12, raw.size - 12) } catch (_: java.security.GeneralSecurityException) { throw bad }
            try { return JSONObject(String(plain, Charsets.UTF_8)).also { require(it.length() > 0) { "Config is empty" } }.toString() }
            finally { plain.fill(0) }
        }
        if (raw.size < 16 + 12 + 16 + 4) throw bad
        val salt = raw.copyOfRange(0, 16)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, sealKey(salt), GCMParameterSpec(128, raw.copyOfRange(16, 28)))
        c.updateAAD(salt)
        val plain = try { c.doFinal(raw, 28, raw.size - 28) } catch (_: java.security.GeneralSecurityException) { throw bad }
        try {
            val n = ((plain[0].toInt() and 0xff) shl 24) or ((plain[1].toInt() and 0xff) shl 16) or
                ((plain[2].toInt() and 0xff) shl 8) or (plain[3].toInt() and 0xff)
            if (n <= 0 || n > plain.size - 4) throw bad
            val obj = JSONObject(String(plain, 4, n, Charsets.UTF_8))
            if (obj.length() == 0) throw bad
            return obj.toString()
        } finally { plain.fill(0) }
    }

    /** What the file header says (not authenticated; a UI hint only): {"password":bool,"device":bool}. */
    fun hint(text: String): String = if (isOpen(text)) "{\"password\":false,\"device\":false,\"open\":true}" else try {
        val i = HJ01.inspect(dearmor(text))
        JSONObject().put("password", i.hasPassword).put("device", i.hasRecipient).toString()
    } catch (_: Exception) { "{\"password\":true,\"device\":false}" }

    private fun armor(bytes: ByteArray) = HJ01.PREFIX +
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun dearmor(text: String): ByteArray = try {
        Base64.decode(text.trim().removePrefix(HJ01.PREFIX).filter { !it.isWhitespace() }, Base64.URL_SAFE)
    } catch (_: IllegalArgumentException) { throw IllegalArgumentException("This HJ file is damaged") }

    /** Password-protected HJ01 export (the only locked format this app writes). Verified before it is returned. */
    fun encrypt(ctx: Context, configJson: String, password: String): String =
        encryptFor(ctx, configJson, password, emptyList(), 0L, 0)

    /**
     * HJ01 export with any mix of: a password, recipient/device public keys (base64 X.509, see HJDeviceKey),
     * an expiry (epoch seconds, 0 = none) and an import limit (0 = unlimited).
     */
    fun encryptFor(ctx: Context, configJson: String, password: String?, recipientKeys: List<String>,
                   expiresSec: Long, maxImports: Int): String {
        val hasPw = !password.isNullOrEmpty()
        if (hasPw) require(password!!.length >= 10) { "Use a configuration password of at least 10 characters" }
        require(hasPw || recipientKeys.isNotEmpty()) { "Set a password or choose a recipient device" }
        val plain = JSONObject(configJson).toString().toByteArray(Charsets.UTF_8)
        val o = HJ01.Options()
        if (hasPw) {
            o.password = password!!.toCharArray()
            val a = HJGuard.argon(ctx)
            o.memKiB = a.memKiB; o.iters = a.iters; o.lanes = a.lanes
        }
        recipientKeys.forEach { o.recipients.add(Base64.decode(it.trim(), Base64.DEFAULT)) }
        o.expiresSec = expiresSec; o.maxImports = maxImports
        return try {
            armor(HJ01.encrypt(plain, o))
        } catch (e: HJ01.HJException) {
            throw IllegalArgumentException(e.message)
        } finally {
            plain.fill(0); o.password?.fill('\u0000')
        }
    }

    /**
     * Opens an HJ01 file. Order: structure check -> attempt limiter -> unwrap the file key -> GCM verifies the whole
     * header and payload -> import limit -> schema check. A wrong password or edited file yields no data.
     */
    fun openHJ01(ctx: Context, text: String, password: String): String {
        val bytes = dearmor(text)
        val info = try { HJ01.inspect(bytes) } catch (e: HJ01.HJException) { throw IllegalArgumentException(e.message) }
        val fid = info.fileId.joinToString("") { "%02x".format(it) }
        HJGuard.checkAllowed(ctx, fid)
        val cred = HJ01.Credentials()
        val pw = password.toCharArray()
        if (pw.isNotEmpty()) cred.password(pw)
        cred.device(HJDeviceKey.get())
        val result = try {
            HJ01.decrypt(bytes, cred, System.currentTimeMillis() / 1000)
        } catch (e: HJ01.AuthException) {
            HJGuard.failed(ctx, fid); throw IllegalArgumentException(e.message)
        } catch (e: HJ01.HJException) {
            throw IllegalArgumentException(e.message)
        } finally { pw.fill('\u0000') }
        try {
            HJGuard.succeeded(ctx, fid)
            HJGuard.consumeImport(ctx, fid, result.maxImports)
            val obj = JSONObject(String(result.plaintext, Charsets.UTF_8))
            require(obj.length() > 0) { "HJ file has no configuration" }
            return obj.toString()
        } finally { result.plaintext.fill(0) }
    }

    /** Legacy JSON containers (v1/v2). Import only. */
    fun decryptLegacy(containerText: String, password: String): String {
        val box = JSONObject(containerText)
        require(box.optString("format") == FORMAT) { "Unsupported HJ file" }
        val version = box.optInt("version", -1)
        require(version == LEGACY_VERSION || version == VERSION) { "Unsupported HJ file version" }
        require(box.optBoolean("locked", false)) { "This HJ file is not password locked" }
        require(box.optString("kdf") == "PBKDF2-HMAC-SHA256") { "Unsupported HJ key derivation" }
        val iterations = box.optInt("iterations", -1)
        require(iterations in 100_000..1_000_000) { "Invalid HJ key derivation parameters" }
        val saltText = box.getString("salt")
        val ivText = box.getString("iv")
        val salt = Base64.decode(saltText, Base64.NO_WRAP)
        val iv = Base64.decode(ivText, Base64.NO_WRAP)
        val encrypted = Base64.decode(box.getString("ciphertext"), Base64.NO_WRAP)
        require(salt.size == 16 && iv.size == 12 && encrypted.size >= 16) { "Invalid HJ file data" }

        val aad = if (version == LEGACY_VERSION) LEGACY_AAD
            else authenticatedHeader(version, iterations, saltText, ivText)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, derive(password, salt, iterations), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val plain = cipher.doFinal(encrypted)
        return try {
            JSONObject(String(plain, Charsets.UTF_8)).toString()
        } finally {
            plain.fill(0)
        }
    }

    fun open(containerText: String): String {
        val box = JSONObject(containerText)
        require(box.optString("format") == FORMAT) { "Unsupported HJ file" }
        require(box.optInt("version", -1) in LEGACY_VERSION..VERSION) { "Unsupported HJ file version" }
        require(!box.optBoolean("locked", false)) { "This HJ file requires a password" }
        // An encrypted envelope cannot be downgraded by editing only `locked`.
        require(encryptedFields.none { box.has(it) }) { "Encrypted HJ envelope cannot be opened as an unlocked file" }
        val config = box.optJSONObject("config") ?: throw IllegalArgumentException("HJ file has no configuration")
        return config.toString()
    }

    private fun authenticatedHeader(version: Int, iterations: Int, salt: String, iv: String): String =
        "$FORMAT|$version|locked=true|PBKDF2-HMAC-SHA256|$iterations|$salt|$iv"

    private fun derive(password: String, salt: ByteArray, iterations: Int): SecretKeySpec {
        val chars = password.toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, 256)
        chars.fill('\u0000')
        return try {
            val bytes = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", BouncyCastleProvider())
                .generateSecret(spec).encoded
            try { SecretKeySpec(bytes, "AES") } finally { bytes.fill(0) }
        } finally {
            spec.clearPassword()
        }
    }
}
