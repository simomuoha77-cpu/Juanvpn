package com.juanvpn.app

import android.content.Context
import android.os.Build
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager

/**
 * Which mobile carrier the data is really on.
 *
 * The old log line used the network's broadcast display name, and some carriers broadcast a promotion there
 * (Airtel Kenya shows "SaveNaAirtelMoney"). Here the name comes from the SIM that carries mobile data, so it is the
 * real carrier in any country and it follows the data SIM on dual-SIM phones.
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

    /** Names confirmed for Kenya (MCC 639). Everything else comes from Android's own carrier database, see [name]. */
    fun nameFor(code: String): String? = when (code) {
        "63901", "63902" -> "Safaricom"
        "63903" -> "Airtel"
        "63907" -> "Telkom"
        else -> null
    }

    /**
     * Real carrier of the data SIM, worldwide. Order:
     *  1. confirmed Kenyan MCC-MNC names above;
     *  2. Android's carrier ID database for the SIM (Android 9+, covers carriers in every country);
     *  3. a Kenyan code on the network side (no usable SIM code);
     *  4. the name the SIM itself reports, then the network's, as a last resort.
     * On Android 6 to 8 there is no carrier database, so step 2 is skipped and other countries show step 4.
     */
    fun name(ctx: Context): String {
        val tm = dataTm(ctx) ?: return "Mobile"
        return try {
            nameFor(tm.simOperator.orEmpty())
                ?: (if (Build.VERSION.SDK_INT >= 28) tm.simCarrierIdName?.toString()?.trim()?.takeIf { it.isNotEmpty() } else null)
                ?: nameFor(tm.networkOperator.orEmpty())
                ?: tm.simOperatorName.ifBlank { tm.networkOperatorName }.ifBlank { "Mobile" }
        } catch (_: Throwable) { "Mobile" }
    }
}
