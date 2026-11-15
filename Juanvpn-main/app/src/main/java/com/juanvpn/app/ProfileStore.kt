package com.juanvpn.app

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

class ProfileStore(context: Context) {
    private val prefs = EncryptedSharedPreferences.create(context, "juan_secure_profiles",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    fun save(profile: Profile) { prefs.edit().putString("active", profile.toJson().toString()).apply() }
    fun load(): Profile = try { Profile.fromJson(JSONObject(prefs.getString("active", "") ?: "")) } catch (_: Exception) { Profile() }
}
