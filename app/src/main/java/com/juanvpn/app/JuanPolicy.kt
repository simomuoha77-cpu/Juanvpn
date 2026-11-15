package com.juanvpn.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale

/** Stable per-install user ID, shown in the app and used for device-locked configs. */
object DeviceId {
    fun get(ctx: Context): String {
        val sp = ctx.getSharedPreferences("juan_device", Context.MODE_PRIVATE)
        sp.getString("id", null)?.let { return it }
        val aid = try { Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID) } catch (_: Exception) { null }
        val seed = if (aid.isNullOrBlank() || aid == "9774d56d682e549c") java.util.UUID.randomUUID().toString() else aid
        val h = MessageDigest.getInstance("SHA-256").digest(("juanvpn|" + seed).toByteArray()).joinToString("") { "%02X".format(it) }
        val id = "JV-" + h.substring(0, 16).chunked(4).joinToString("-")
        sp.edit().putString("id", id).apply()
        return id
    }
}

/** Restrictions carried inside an imported .HJ config. Client-side checks: they stop normal users, not a modified APK. */
object JuanPolicy {
    @Volatile var blockTorrent = false
    private val torrentPorts: Set<Int> = (6881..6999).toSet() + setOf(51413, 6969, 2710, 1337)

    /** Best effort: known BitTorrent ports and tracker host names. */
    fun blocked(host: String, port: Int): Boolean {
        if (!blockTorrent) return false
        if (port in torrentPorts) return true
        val h = host.lowercase()
        return h.startsWith("tracker.") || h.startsWith("announce.") || h.contains("torrent")
    }

    fun apply(ctx: Context, c: JuanCfg): JuanCfg {
        val p = c.policy
        blockTorrent = p?.optBoolean("disallowTorrent", false) == true
        return if (p?.optBoolean("loginSshDeviceId", false) == true && c.tunnel == "ssh") c.copy(user = DeviceId.get(ctx)) else c
    }

    fun check(ctx: Context, c: JuanCfg): String? {
        val p = c.policy ?: return null
        val expiry = p.optString("expiry", "")
        if (expiry.isNotBlank()) {
            val end = try { SimpleDateFormat("yyyy-MM-dd", Locale.US).apply { isLenient = false }.parse(expiry) }
            catch (_: Exception) { return "This configuration has an invalid expiry date." }
            if (end == null || System.currentTimeMillis() >= end.time + 24L * 3600 * 1000) return "This configuration expired on $expiry."
        }
        val ids = p.optJSONArray("deviceIds")
        if (ids != null && ids.length() > 0) {
            val me = DeviceId.get(ctx)
            if (!(0 until ids.length()).any { ids.optString(it).trim().equals(me, true) })
                return "This configuration is locked to other devices. Your Device ID: $me"
        }
        if (p.optBoolean("mobileDataOnly", false)) {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) || caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                return "This configuration works on mobile data only. Turn off Wi-Fi and try again."
        }
        val ops = p.optJSONArray("operators")
        if (ops != null && ops.length() > 0) {
            val sim = ctx.getSystemService(TelephonyManager::class.java)?.simOperator.orEmpty()
            if (sim.isBlank() || !(0 until ops.length()).any { ops.optString(it).trim() == sim })
                return "This configuration is locked to another mobile operator." + if (sim.isNotBlank()) " (Your SIM: $sim)" else " (No SIM detected)"
        }
        if (p.optBoolean("blockRooted", false) && isRooted()) return "This configuration does not run on rooted devices."
        if (p.optBoolean("playStoreOnly", false)) {
            val installer = if (Build.VERSION.SDK_INT >= 30) try { ctx.packageManager.getInstallSourceInfo(ctx.packageName).installingPackageName } catch (_: Exception) { null }
            else ctx.packageManager.getInstallerPackageName(ctx.packageName)
            if (installer != "com.android.vending") return "This configuration only works with the Google Play version of JUAN VPN."
        }
        return null
    }

    fun isRooted(): Boolean {
        if (Build.TAGS?.contains("test-keys") == true) return true
        val paths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/su/bin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/app/Superuser.apk", "/system/xbin/daemonsu")
        return paths.any { File(it).exists() }
    }

    fun gamePackages(ctx: Context): List<String> =
        ctx.packageManager.getInstalledApplications(0).filter { ai ->
            ai.packageName != ctx.packageName &&
                ((Build.VERSION.SDK_INT >= 26 && ai.category == ApplicationInfo.CATEGORY_GAME) ||
                    (ai.flags and ApplicationInfo.FLAG_IS_GAME) != 0)
        }.map { it.packageName }
}
