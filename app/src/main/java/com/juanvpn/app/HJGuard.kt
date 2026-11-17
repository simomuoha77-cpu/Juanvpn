package com.juanvpn.app

import android.content.Context

/**
 * App-side limits around HJ01 files: failed-password delays, per-file import limits and the cached Argon2id
 * settings for this phone.
 *
 * Honest limits: this state lives on the phone. It slows guessing inside the app and enforces a file's import limit
 * for honest use, but it does not stop someone who copies the file and attacks it offline (the Argon2id cost and the
 * password strength do that), and uninstalling the app resets the counters.
 */
object HJGuard {
    private const val PREFS = "hj_guard"
    private const val FREE_TRIES = 3
    private const val BASE_DELAY_MS = 5_000L
    private const val MAX_DELAY_MS = 15 * 60_000L

    private fun p(c: Context) = c.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Delay after n consecutive failures: none for the first 3, then 5 s, 10 s, 20 s ... capped at 15 min. */
    internal fun delayFor(n: Int): Long =
        if (n <= FREE_TRIES) 0L else minOf(BASE_DELAY_MS shl minOf(n - FREE_TRIES - 1, 20), MAX_DELAY_MS)

    @Synchronized fun checkAllowed(c: Context, fileId: String) {
        val now = System.currentTimeMillis()
        val until = maxOf(p(c).getLong("until_$fileId", 0L), p(c).getLong("until_all", 0L))
        if (until > now) throw IllegalArgumentException("Too many wrong attempts. Try again in ${(until - now + 999) / 1000} seconds")
    }

    @Synchronized fun failed(c: Context, fileId: String) {
        val sp = p(c); val now = System.currentTimeMillis()
        val nf = sp.getInt("fail_$fileId", 0) + 1
        val na = sp.getInt("fail_all", 0) + 1
        sp.edit().putInt("fail_$fileId", nf).putLong("until_$fileId", now + delayFor(nf))
            .putInt("fail_all", na).putLong("until_all", now + delayFor(na)).commit()
    }

    @Synchronized fun succeeded(c: Context, fileId: String) {
        p(c).edit().remove("fail_$fileId").remove("until_$fileId").remove("fail_all").remove("until_all").commit()
    }

    /** Called only after the file authenticated. max = 0 means unlimited. */
    @Synchronized fun consumeImport(c: Context, fileId: String, max: Int) {
        if (max <= 0) return
        val used = p(c).getInt("imp_$fileId", 0)
        if (used >= max) throw IllegalArgumentException("This file has reached its import limit")
        p(c).edit().putInt("imp_$fileId", used + 1).commit()
    }

    /** Argon2id settings measured on this phone once (about 0.6 s, at most 64 MiB), then reused. */
    @Synchronized fun argon(c: Context): HJ01.Argon2Choice {
        val sp = p(c)
        val m = sp.getInt("a_mem", 0); val t = sp.getInt("a_it", 0)
        if (m >= 19_456 && t >= 2) return HJ01.choice(m, t, 1)
        val ch = HJ01.calibrate(600, 65_536)
        sp.edit().putInt("a_mem", ch.memKiB).putInt("a_it", ch.iters).commit()
        return ch
    }
}
