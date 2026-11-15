package com.juanvpn.app

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object AppLog {
    private const val PREFS = "juan_session"
    private const val LOG_KEY = "logs"
    private const val STATE_KEY = "state"
    @Synchronized fun write(context: Context, message: String) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val old = prefs.getString(LOG_KEY, "").orEmpty()
        val next = (old + "[$stamp] $message\n").lines().takeLast(250).joinToString("\n")
        prefs.edit().putString(LOG_KEY, next).apply()
    }
    fun read(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(LOG_KEY, "")
            ?.ifBlank { "No connection events yet." } ?: "No connection events yet."
    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(LOG_KEY).apply()
    }
    fun setState(context: Context, state: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(STATE_KEY, state).apply()
    }
}
