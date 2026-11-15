package com.juanvpn.app

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.util.Date

/** Saves the last crash so it can be shown in the Log tab after restart. */
object JuanCrash {
    fun install(c: Context) {
        val app = c.applicationContext
        val old = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try { File(app.filesDir, "crash.txt").writeText("${Date()} thread=${t.name}\n" + Log.getStackTraceString(e).take(3000)) } catch (_: Throwable) {}
            old?.uncaughtException(t, e)
        }
    }

    fun report(c: Context): String? {
        val sb = StringBuilder()
        val f = File(c.filesDir, "crash.txt")
        if (f.exists()) { sb.append("Last crash:\n").append(f.readText()); f.delete() }
        if (Build.VERSION.SDK_INT >= 30) try {
            val sp = c.getSharedPreferences("juan_crash", Context.MODE_PRIVATE)
            c.getSystemService(ActivityManager::class.java).getHistoricalProcessExitReasons(c.packageName, 0, 1).firstOrNull()?.let {
                val bad = it.reason !in listOf(ApplicationExitInfo.REASON_EXIT_SELF, ApplicationExitInfo.REASON_USER_REQUESTED,
                    ApplicationExitInfo.REASON_USER_STOPPED)
                if (bad && it.timestamp > sp.getLong("ts", 0)) {
                    sp.edit().putLong("ts", it.timestamp).apply()
                    sb.append("\nLast exit: reason=${it.reason} status=${it.status} ${it.description ?: ""}")
                }
            }
        } catch (_: Throwable) {}
        return sb.toString().ifBlank { null }
    }
}
