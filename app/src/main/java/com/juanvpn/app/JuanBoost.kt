package com.juanvpn.app

import android.content.Context

/**
 * Remembers servers that police extra logins (they closed an extra SSH link, or dropped the main one right after
 * one), so parallel links stay off for them. The mark expires after 24 hours so a wrong guess heals by itself.
 */
object JuanBoost {
    private const val DAY = 24L * 3_600_000L
    @Volatile private var app: Context? = null
    private val mem = java.util.concurrent.ConcurrentHashMap<String, Long>()

    fun init(c: Context) { app = c.applicationContext }

    private fun sp() = app?.getSharedPreferences("juan_boost", Context.MODE_PRIVATE)

    fun off(key: String) {
        val now = System.currentTimeMillis()
        mem[key] = now
        try { sp()?.edit()?.putLong(key, now)?.apply() } catch (_: Throwable) {}
    }

    fun isOff(key: String): Boolean {
        val ts = mem[key] ?: (try { sp()?.getLong(key, 0L) ?: 0L } catch (_: Throwable) { 0L })
        return ts > 0 && System.currentTimeMillis() - ts < DAY
    }
}
