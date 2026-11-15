package com.juanvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** UI <-> service channel. */
object JuanBus {
    @Volatile var state = "DISCONNECTED"; @Volatile var detail = ""; @Volatile var error = ""
    val logs = ArrayList<String>()
    @Volatile var onState: ((String, String, String) -> Unit)? = null
    @Volatile var onLog: ((String) -> Unit)? = null
    @Volatile var onStats: ((JSONObject) -> Unit)? = null
    @Volatile var onHostKey: ((String, String, String) -> Unit)? = null
    @Volatile var pendingHK: Triple<String, String, String>? = null
    @Volatile var answer = false
    @Volatile var latch: java.util.concurrent.CountDownLatch? = null
    @Synchronized fun log(m: String) {
        val l = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date()) + "  " + m
        logs.add(l); if (logs.size > 400) logs.removeAt(0); onLog?.invoke(l)
    }
}

/** Packet engine wrapper. Native stop is only called after a successful start. */
object TunEngine {
    private const val CLS = "hev.htproxy.TProxyService"
    const val DNS = "10.10.10.3"
    @Volatile private var started = false

    @Synchronized fun start(ctx: Context, fd: Int, socksPort: Int) {
        if (started) stop()
        val cfg = File(ctx.cacheDir, "hev.yml")
        cfg.writeText(
            "tunnel:\n  mtu: 1500\n  ipv4: 10.10.10.2\n" +
            "socks5:\n  port: $socksPort\n  address: 127.0.0.1\n  udp: 'tcp'\n" +
            "mapdns:\n  address: $DNS\n  port: 53\n  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 10000\n" +
            "misc:\n  task-stack-size: 86016\n  connect-timeout: 10000\n  tcp-read-write-timeout: 60000\n  udp-read-write-timeout: 60000\n  log-level: warn\n"
        )
        try {
            val k = Class.forName(CLS)
            val method = k.getMethod("TProxyStartService", String::class.java, Int::class.javaPrimitiveType)
            val ok = method.invoke(null, cfg.absolutePath, fd) as? Boolean
            if (ok == false) throw IllegalStateException("TUN engine refused to start. Check its configuration and native library.")
            started = true
        } catch (e: Throwable) {
            started = false
            val root = e.cause ?: e
            throw IllegalStateException("Unable to start the native TUN engine: ${root.message ?: root.javaClass.simpleName}", root)
        }
    }

    @Synchronized fun stop() {
        if (!started) return
        try {
            val k = Class.forName(CLS)
            k.getMethod("TProxyStopService").invoke(null)
        } catch (_: Throwable) {
            // Teardown must never crash the VPN service if native code is unavailable.
        } finally {
            started = false
        }
    }
}

class JuanVpnService : VpnService() {
    companion object { const val START = "juan.START"; const val STOP = "juan.STOP"; const val CFG = "cfg"; private const val NID = 42 }

    private var engine: JuanSshEngine? = null
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private val sched = Executors.newSingleThreadScheduledExecutor()
    private var statsJob: ScheduledFuture<*>? = null
    private var t0 = 0L

    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        if (i?.action == STOP) { teardown(); post("DISCONNECTED", "", ""); stopSelf(); return START_NOT_STICKY }
        val json = i?.getStringExtra(CFG) ?: run { stopSelf(); return START_NOT_STICKY }
        channel()
        ServiceCompat.startForeground(this, NID, notif("Connecting…"),
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0)
        teardown()
        worker = Thread { connectFlow(json) }.apply { name = "JuanConnect"; start() }
        return START_NOT_STICKY
    }

    private fun connectFlow(json: String) {
        try {
            val c = JuanCfg.parse(json)
            c.validate()?.let { throw IllegalArgumentException(it) }
            post("CONNECTING", "Opening SSH tunnel", "")
            val e = JuanSshEngine(c, JuanBus::log, trust()); e.start(); engine = e
            post("CONNECTING", "Starting TUN", "")
            val pfd = build(c) ?: throw IllegalStateException("VPN permission missing or revoked")
            tun = pfd
            TunEngine.start(this, pfd.fd, e.socksPort)
            JuanBus.log("TUN: packet engine started")
            post("CONNECTING", "Checking tunnel", "")
            if (!e.probe()) throw IllegalStateException("SSH is up but no traffic passed through the tunnel")
            t0 = System.currentTimeMillis()
            post("CONNECTED", "${c.user}@${c.sshHost}", "")
            startStats(e)
        } catch (ex: Throwable) {
            val msg = JuanSshEngine.friendly(ex.cause ?: ex)
            JuanBus.log("Error: $msg")
            teardown(); post("ERROR", "", msg); stopSelf()
        }
    }

    private fun build(c: JuanCfg): ParcelFileDescriptor? {
        val b = Builder().setSession("JUAN VPN").setMtu(1500)
            .addAddress("10.10.10.2", 32).addRoute("0.0.0.0", 0).addDnsServer(TunEngine.DNS)
            .addAddress("fd00:10:10::2", 128).addRoute("::", 0) // IPv6 blackholed: no leaks, tunnel is IPv4-only
        when (c.appMode) {
            "inc" -> if (c.apps.isEmpty()) { JuanBus.log("Apps filter: nothing selected, routing all apps"); b.addDisallowedApplication(packageName) }
                     else c.apps.forEach { try { b.addAllowedApplication(it) } catch (_: Exception) {} }
            "exc" -> { c.apps.forEach { try { b.addDisallowedApplication(it) } catch (_: Exception) {} }; b.addDisallowedApplication(packageName) }
            else -> b.addDisallowedApplication(packageName) // our own SSH socket must bypass the TUN
        }
        return b.establish()
    }

    private fun trust() = object : HostTrust {
        val sp = getSharedPreferences("juan_trust", MODE_PRIVATE)
        override fun stored(label: String): String? = sp.getString(label, null)
        override fun save(line: String) { sp.edit().putString(line.substringBefore(' '), line).apply() }
        override fun confirm(host: String, type: String, fingerprint: String): Boolean {
            val l = java.util.concurrent.CountDownLatch(1)
            JuanBus.answer = false; JuanBus.latch = l; JuanBus.pendingHK = Triple(host, type, fingerprint)
            JuanBus.log("Host key: waiting for your confirmation ($type $fingerprint)")
            post("CONNECTING", "Confirm server key", "")
            JuanBus.onHostKey?.invoke(host, type, fingerprint)
            l.await(120, TimeUnit.SECONDS)
            JuanBus.pendingHK = null
            return JuanBus.answer
        }
    }

    private fun startStats(e: JuanSshEngine) {
        var lu = 0L; var ld = 0L
        statsJob = sched.scheduleAtFixedRate({
            val u = e.up.get(); val d = e.down.get()
            JuanBus.onStats?.invoke(JSONObject().put("up", u).put("down", d).put("upBps", u - lu).put("downBps", d - ld)
                .put("uptime", (System.currentTimeMillis() - t0) / 1000))
            lu = u; ld = d
            if (!e.alive()) { JuanBus.log("Tunnel: SSH session lost"); teardown(); post("ERROR", "", "SSH session dropped"); stopSelf() }
        }, 1, 1, TimeUnit.SECONDS)
    }

    private fun post(s: String, d: String, e: String) {
        JuanBus.state = s; JuanBus.detail = d; JuanBus.error = e
        JuanBus.log("State: $s${if (d.isNotEmpty()) " ($d)" else ""}")
        JuanBus.onState?.invoke(s, d, e)
        getSystemService(NotificationManager::class.java).notify(NID, notif(if (e.isNotEmpty()) e else s.lowercase().replaceFirstChar { it.uppercase() } + if (d.isNotEmpty()) " · $d" else ""))
    }

    private fun teardown() {
        statsJob?.cancel(false); statsJob = null
        TunEngine.stop()
        try { tun?.close() } catch (_: Exception) {}; tun = null
        engine?.stop(); engine = null
        worker?.takeIf { it !== Thread.currentThread() }?.interrupt()
    }

    override fun onRevoke() { teardown(); post("DISCONNECTED", "", "VPN permission revoked"); stopSelf() }
    override fun onDestroy() { teardown(); sched.shutdownNow(); super.onDestroy() }

    private fun channel() {
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel("juan_vpn2", "JUAN VPN session", NotificationManager.IMPORTANCE_LOW))
    }

    private fun notif(text: String): Notification {
        val stop = PendingIntent.getService(this, 0, Intent(this, JuanVpnService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        val open = PendingIntent.getActivity(this, 1, Intent(this, JuanWebActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, "juan_vpn2").setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("JUAN VPN").setContentText(text).setOngoing(true).setContentIntent(open)
            .addAction(0, "Disconnect", stop).build()
    }
}
