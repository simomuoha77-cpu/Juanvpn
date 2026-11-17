package com.juanvpn.app

import android.content.Context
import android.os.Build
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager

/**
 * Which mobile carrier the data is really on.
 *
 * The old log line used the network's broadcast display name, and some carriers broadcast a promotion there
 * (Airtel Kenya shows "SaveNaAirtelMoney"). Here the name comes from the MCC-MNC code of the SIM that carries
 * mobile data, so it is the real carrier and it follows the data SIM on dual-SIM phones.
 */
object Carrier {
    /** TelephonyManager of the SIM that carries mobile data (the default data subscription). */
    fun dataTm(ctx: Context): TelephonyManager? {
        val base = try { ctx.getSystemService(TelephonyManager::class.java) } catch (_: Throwable) { null } ?: return null
        if (Build.VERSION.SDK_INT < 24) return base
        return try {
            val id = SubscriptionManager.getDefaultDataSubscriptionId()
            if (id != SubscriptionManager.INVALID_SUBSCRIPTION_ID) base.createForSubscriptionId(id) else base
        } catch (_: Throwable) { base }
    }

    /** MCC+MNC of the SIM in the data slot, for example "63902". Blank when there is no SIM or it is unreadable. */
    fun simCode(ctx: Context): String = try { dataTm(ctx)?.simOperator.orEmpty() } catch (_: Throwable) { "" }

    /** Kenya (MCC 639). Other codes return null and the name the SIM itself reports is shown instead. */
    fun nameFor(code: String): String? = when (code) {
        "63901", "63902" -> "Safaricom"
        "63903" -> "Airtel"
        "63907" -> "Telkom"
        else -> null
    }

    fun name(ctx: Context): String {
        val tm = dataTm(ctx) ?: return "Mobile"
        return try {
            nameFor(tm.simOperator.orEmpty()) ?: nameFor(tm.networkOperator.orEmpty())
                ?: tm.simOperatorName.ifBlank { tm.networkOperatorName }.ifBlank { "Mobile" }
        } catch (_: Throwable) { "Mobile" }
    }
}
