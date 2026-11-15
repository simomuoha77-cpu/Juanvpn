package com.juanvpn.app

import android.util.Base64
import org.json.JSONObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** Authenticated, password-protected JUAN HJ configuration container. */
object HJConfig {
    private const val FORMAT = "JUAN-HJ"
    private const val VERSION = 1
    private const val ITERATIONS = 310_000
    private const val AAD = "JUAN-HJ|1"
    private val random = SecureRandom()

    fun unlocked(configJson: String): String {
        val config = JSONObject(configJson)
        return JSONObject().put("format", FORMAT).put("version", VERSION)
            .put("locked", false).put("config", config).toString(2)
    }

    fun encrypt(configJson: String, password: String): String {
        require(password.length >= 10) { "Use a configuration password of at least 10 characters" }
        val salt = ByteArray(16).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val key = derive(password, salt, ITERATIONS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        cipher.updateAAD(AAD.toByteArray(Charsets.UTF_8))
        val encrypted = cipher.doFinal(JSONObject(configJson).toString().toByteArray(Charsets.UTF_8))
        return JSONObject().put("format", FORMAT).put("version", VERSION).put("locked", true)
            .put("kdf", "PBKDF2-HMAC-SHA256").put("iterations", ITERATIONS)
            .put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP)).toString(2)
    }

    fun decrypt(containerText: String, password: String): String {
        val box = JSONObject(containerText)
        require(box.optString("format") == FORMAT && box.optInt("version") == VERSION) { "Unsupported HJ file" }
        require(box.optBoolean("locked", false)) { "This HJ file is not password locked" }
        require(box.optString("kdf") == "PBKDF2-HMAC-SHA256") { "Unsupported HJ key derivation" }
        val iterations = box.optInt("iterations", -1)
        require(iterations in 100_000..1_000_000) { "Invalid HJ key derivation parameters" }
        val salt = Base64.decode(box.getString("salt"), Base64.NO_WRAP)
        val iv = Base64.decode(box.getString("iv"), Base64.NO_WRAP)
        val encrypted = Base64.decode(box.getString("ciphertext"), Base64.NO_WRAP)
        require(salt.size == 16 && iv.size == 12 && encrypted.size >= 16) { "Invalid HJ file data" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, derive(password, salt, iterations), GCMParameterSpec(128, iv))
        cipher.updateAAD(AAD.toByteArray(Charsets.UTF_8))
        return JSONObject(String(cipher.doFinal(encrypted), Charsets.UTF_8)).toString()
    }

    fun open(containerText: String): String {
        val box = JSONObject(containerText)
        require(box.optString("format") == FORMAT && box.optInt("version") == VERSION) { "Unsupported HJ file" }
        require(!box.optBoolean("locked", false)) { "This HJ file requires a password" }
        return box.getJSONObject("config").toString()
    }

    private fun derive(password: String, salt: ByteArray, iterations: Int): SecretKeySpec {
        val chars = password.toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, 256)
        chars.fill('\u0000')
        return try {
            val bytes = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", BouncyCastleProvider()).generateSecret(spec).encoded
            try { SecretKeySpec(bytes, "AES") } finally { bytes.fill(0) }
        } finally { spec.clearPassword() }
    }
}
