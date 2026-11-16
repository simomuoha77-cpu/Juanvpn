package com.juanvpn.app

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Passwords and keys. Stored in Keystore-backed EncryptedSharedPreferences.
 *
 * On some phones the Android Keystore breaks (screen-lock change, OEM bugs, restored backups) and the encrypted
 * store becomes unreadable or unwritable. Before, that failure was swallowed and the app carried on with empty
 * or old credentials, which showed up as "wrong username, password or key" until the config was imported again.
 * Now writes are committed, a broken store is rebuilt, and if the Keystore still refuses, the secrets are kept in
 * an app-private encrypted file instead, so a saved login is never silently lost.
 * Saving merges into what is stored, so changing one field can never blank the others.
 */
object JuanSecrets {
    private const val PREFS = "juan_secrets"

    private fun prefs(c: Context) = EncryptedSharedPreferences.create(c, PREFS,
        MasterKey.Builder(c).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)

    private fun readPrimary(c: Context): String? = try { prefs(c).getString("s", null) } catch (_: Throwable) { null }
    private fun writePrimary(c: Context, v: String): Boolean = try { prefs(c).edit().putString("s", v).commit() } catch (_: Throwable) { false }

    /** Throws the unreadable store away (its Keystore key is gone or invalid) so a fresh one can be created. */
    private fun resetPrimary(c: Context) {
        try { c.deleteSharedPreferences(PREFS) } catch (_: Throwable) {}
        try { java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry("_androidx_security_master_key_") } } catch (_: Throwable) {}
    }

    // ---- fallback: used only while the Keystore is unusable ----
    private fun dataFile(c: Context) = File(c.noBackupFilesDir, "juan_s.dat")
    private fun keyFile(c: Context) = File(c.noBackupFilesDir, "juan_s.key")

    private fun fbKey(c: Context): SecretKeySpec {
        val f = keyFile(c)
        val raw = if (f.exists() && f.length() == 32L) f.readBytes() else ByteArray(32).also { SecureRandom().nextBytes(it); f.writeBytes(it) }
        return SecretKeySpec(raw, "AES")
    }

    private fun writeFallback(c: Context, v: String) = try {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val ci = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, fbKey(c), GCMParameterSpec(128, iv)) }
        dataFile(c).writeBytes(iv + ci.doFinal(v.toByteArray(Charsets.UTF_8)))
    } catch (_: Throwable) {}

    private fun readFallback(c: Context): String? = try {
        val f = dataFile(c)
        if (!f.exists()) null else {
            val b = f.readBytes()
            val ci = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, fbKey(c), GCMParameterSpec(128, b.copyOfRange(0, 12))) }
            String(ci.doFinal(b, 12, b.size - 12), Charsets.UTF_8)
        }
    } catch (_: Throwable) { null }

    private fun dropFallback(c: Context) { try { dataFile(c).delete(); keyFile(c).delete() } catch (_: Throwable) {} }

    @Synchronized fun load(c: Context): String = readFallback(c) ?: readPrimary(c) ?: "{}"

    /** Merges the given fields into the stored secrets (a blank value clears that field). */
    @Synchronized fun save(c: Context, json: String) {
        val cur = try { JSONObject(load(c)) } catch (_: Throwable) { JSONObject() }
        try { val inc = JSONObject(json); inc.keys().forEach { cur.put(it, inc.get(it)) } } catch (_: Throwable) { return }
        val out = cur.toString()
        if (writePrimary(c, out)) { dropFallback(c); return }
        resetPrimary(c)
        if (writePrimary(c, out)) { dropFallback(c); return }
        writeFallback(c, out)
    }
}
