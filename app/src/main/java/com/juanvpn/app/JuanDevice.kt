package com.juanvpn.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.TelephonyManager
import java.net.Inet4Address
import java.net.NetworkInterface

/** Device and network lines for the top of the log, e.g. "Airtel (KE) / LTE (4G)" and "Local IP 10.45.129.205". */
object JuanDevice {
    fun staticLines(ctx: Context): List<String> {
        val ver = try { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName } catch (_: Exception) { "" }
        val maker = Build.MANUFACTURER.replaceFirstChar { it.uppercase() }
        return listOf(
            "JUAN VPN v$ver",
            "running on $maker (${Build.MODEL})",
            "engines: Hysteria " + (if (JuanProc.binary(ctx, "hysteria") != null) "yes" else "no") + ", DNSTT " + (if (JuanProc.binary(ctx, "dnstt") != null) "yes" else "no"),
            "Android ${Build.VERSION.RELEASE} API-${Build.VERSION.SDK_INT} (${Build.SUPPORTED_ABIS.firstOrNull() ?: "?"})"
        )
    }

    fun networkLines(ctx: Context): List<String> =
        listOf(networkLine(ctx), "Local IP " + (localIp(ctx) ?: "not available"))

    fun header(ctx: Context): List<String> = staticLines(ctx) + networkLines(ctx)

    private fun underlying(ctx: Context): NetworkCapabilities? = try {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION")
        cm.allNetworks.mapNotNull { cm.getNetworkCapabilities(it) }
            .firstOrNull { !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) }
    } catch (_: Throwable) { null }

    private fun networkLine(ctx: Context): String {
        val caps = underlying(ctx) ?: return "No network"
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "Wi-Fi"
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "Ethernet"
        val tm = Carrier.dataTm(ctx) ?: return "Mobile data"
        val op = Carrier.name(ctx)
        val cc = tm.networkCountryIso.ifBlank { tm.simCountryIso }.uppercase()
        val type = try {
            @Suppress("DEPRECATION", "MissingPermission")
            when (tm.networkType) {
                TelephonyManager.NETWORK_TYPE_NR -> "5G"
                TelephonyManager.NETWORK_TYPE_LTE -> "LTE (4G)"
                TelephonyManager.NETWORK_TYPE_HSPAP, TelephonyManager.NETWORK_TYPE_HSPA, TelephonyManager.NETWORK_TYPE_HSDPA,
                TelephonyManager.NETWORK_TYPE_HSUPA, TelephonyManager.NETWORK_TYPE_UMTS, TelephonyManager.NETWORK_TYPE_EVDO_0,
                TelephonyManager.NETWORK_TYPE_EVDO_A, TelephonyManager.NETWORK_TYPE_EVDO_B -> "3G"
                TelephonyManager.NETWORK_TYPE_EDGE, TelephonyManager.NETWORK_TYPE_GPRS, TelephonyManager.NETWORK_TYPE_CDMA,
                TelephonyManager.NETWORK_TYPE_1xRTT, TelephonyManager.NETWORK_TYPE_IDEN -> "2G"
                else -> "Mobile data"      // unknown, or the Phone permission was not granted
            }
        } catch (_: Throwable) { "Mobile data" }
        return op + (if (cc.isNotEmpty()) " ($cc)" else "") + " / " + type
    }

    /** The phone's own address on the real network (not the VPN), e.g. 10.45.129.205. */
    fun localIp(ctx: Context): String? {
        try {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            @Suppress("DEPRECATION")
            for (n in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                val lp = cm.getLinkProperties(n) ?: continue
                lp.linkAddresses.map { it.address }.firstOrNull { it is Inet4Address && !it.isLoopbackAddress }?.hostAddress?.let { return it }
            }
        } catch (_: Throwable) {}
        try {
            for (ni in NetworkInterface.getNetworkInterfaces()) {
                if (!ni.isUp || ni.isLoopback || ni.name.startsWith("tun") || ni.name.startsWith("dummy")) continue
                ni.inetAddresses.asSequence().firstOrNull { it is Inet4Address && !it.isLoopbackAddress }?.hostAddress?.let { return it }
            }
        } catch (_: Throwable) {}
        return null
    }
}
