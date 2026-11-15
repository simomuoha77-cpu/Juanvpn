package com.juanvpn.app

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/** Keystore-backed storage for passwords and keys. */
object JuanSecrets {
    private fun prefs(c: Context) = EncryptedSharedPreferences.create(c, "juan_secrets",
        MasterKey.Builder(c).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    fun save(c: Context, json: String) { try { prefs(c).edit().putString("s", json).apply() } catch (_: Exception) {} }
    fun load(c: Context): String = try { prefs(c).getString("s", "{}") ?: "{}" } catch (_: Exception) { "{}" }
    fun clear(c: Context) { try { prefs(c).edit().remove("s").apply() } catch (_: Exception) {} }
}
