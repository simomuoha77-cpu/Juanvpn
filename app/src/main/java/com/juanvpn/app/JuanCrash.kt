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
            val text = "${Date()} thread=${t.name}\n" + Log.getStackTraceString(e).take(3000)
            if (t === android.os.Looper.getMainLooper().thread) {
                try { File(app.filesDir, "crash.txt").writeText(text) } catch (_: Throwable) {}
                old?.uncaughtException(t, e)               // a real UI-thread crash still ends the process
            } else {
                // Network and worker threads: keep the app and the VPN running, remember what happened.
                try { File(app.filesDir, "bgerr.txt").writeText(text) } catch (_: Throwable) {}
                try { JuanBus.log("Recovered: ${t.name} ${e.javaClass.simpleName} ${(e.message ?: "").take(80)}") } catch (_: Throwable) {}
            }
        }
    }

    /** Own-process logcat lines (native aborts, fdsan, JNI, hev) from the previous run. */
    fun nativeTail(): String = try {
        val pr = ProcessBuilder("logcat", "-d", "-v", "threadtime", "-t", "1500").redirectErrorStream(true).start()
        val lines = pr.inputStream.bufferedReader().readLines(); pr.destroy()
        val key = Regex("fatal signal|sigsegv|sigabrt|sigbus|fdsan|abort|libc|hev|tproxy|androidruntime|unsatisfied|jni|dlopen|linker|juanvpn", RegexOption.IGNORE_CASE)
        lines.filter { key.containsMatchIn(it) }.takeLast(45).joinToString("\n").ifBlank { "(no matching lines)" }
    } catch (e: Throwable) { "logcat unavailable: ${e.message}" }

    fun report(c: Context): String? {
        val sb = StringBuilder()
        val f = File(c.filesDir, "crash.txt")
        if (f.exists()) { sb.append("Last crash:\n").append(f.readText()); f.delete() }
        val g = File(c.filesDir, "bgerr.txt")
        if (g.exists()) { sb.append("\nBackground error (the app kept running):\n").append(g.readText()); g.delete() }
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
