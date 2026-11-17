package com.juanvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
import java.util.concurrent.atomic.AtomicBoolean

/** UI <-> service channel. */
object JuanBus {
    @Volatile private var appContext: Context? = null
    @Volatile var state = "DISCONNECTED"; @Volatile var detail = ""; @Volatile var error = ""
    @Volatile var publicIp = ""          // IP seen through the tunnel while connected
    @Volatile var socksPort = 0          // local forwarder of the running tunnel
    @Volatile var headerLogged = false
    @Volatile var pingOn = true          // HTTP ping switch (Settings)
    @Volatile var pingUrl = "clients3.google.com/generate_204"
    @Volatile var pingMs = -2            // -2 no data yet, -1 failed, otherwise round trip in ms
    val logs = java.util.Collections.synchronizedList(ArrayList<String>())
    fun init(context: Context) {
        appContext = context.applicationContext
        synchronized(logs) {
            if (logs.isEmpty()) {
                logs.addAll(AppLog.read(context).lineSequence().filter { it.isNotBlank() }.toList().takeLast(1500))
            }
        }
    }
    @Volatile var onState: ((String, String, String) -> Unit)? = null
    @Volatile var onLog: ((String) -> Unit)? = null
    @Volatile var onStats: ((JSONObject) -> Unit)? = null
    @Volatile var onHostKey: ((String, String, String) -> Unit)? = null
    @Volatile var pendingHK: Triple<String, String, String>? = null
    @Volatile var answer = false
    @Volatile var latch: java.util.concurrent.CountDownLatch? = null
    @Synchronized fun addSilent(m: String) {
        val l = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date()) + "  " + m
        synchronized(logs) { logs.add(l); while (logs.size > 1500) logs.removeAt(0) }
        appContext?.let { AppLog.write(it, m) }
    }
    /** Frequent lines (ping): shown live and kept in memory, but not written to the saved session log. */
    @Synchronized fun logLive(m: String) {
        val l = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date()) + "  " + m
        synchronized(logs) { logs.add(l); while (logs.size > 1500) logs.removeAt(0) }
        onLog?.invoke(l)
    }
    @Synchronized fun log(m: String) {
        val l = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date()) + "  " + m
        synchronized(logs) {
            logs.add(l)
            while (logs.size > 1500) logs.removeAt(0)
        }
        appContext?.let { AppLog.write(it, m) }
        onLog?.invoke(l)
    }
}

/** Packet engine: hev-socks5-tunnel. Looked up by reflection so the project builds without it. */
object TunEngine {
    private const val CLS = "hev.htproxy.TProxyService"
    const val DNS = "10.10.10.3"
    @Volatile private var started = false

    /** [tx packets, tx bytes, rx packets, rx bytes] from the packet engine, or null when unavailable. */
    fun stats(): LongArray? = try {
        Class.forName(CLS).getMethod("TProxyGetStats").invoke(null) as? LongArray
    } catch (_: Throwable) { null }

    @Synchronized fun start(ctx: Context, fd: Int, socksPort: Int, udp: Boolean = false) {
        if (started) throw IllegalStateException("TUN engine is already running")
        val cfg = File(ctx.cacheDir, "hev.yml")
        cfg.writeText(
            "tunnel:\n  mtu: 1500\n  ipv4: 10.10.10.2\nsocks5:\n  port: $socksPort\n  address: 127.0.0.1\n" + (if (udp) "  udp: 'udp'\n" else "") +
            "mapdns:\n  address: $DNS\n  port: 53\n  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 10000\n" +
            "misc:\n  task-stack-size: 20480\n  connect-timeout: 5000\n  read-write-timeout: 60000\n  log-level: info\n"
        )
        JuanBus.log("TUN: loading native library")
        val k = try { Class.forName(CLS) } catch (_: ClassNotFoundException) {
            throw IllegalStateException("TUN engine not bundled: add hev-socks5-tunnel (hev.htproxy.TProxyService + libhev-socks5-tunnel.so)")
        }
        try {
            val r = k.getMethod("TProxyStartService", String::class.java, Int::class.javaPrimitiveType).invoke(null, cfg.absolutePath, fd)
            if (r == false) throw IllegalStateException("Native TUN engine refused to start (bad config or interface)")
            started = true
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw IllegalStateException("Native TUN engine failed to start: ${e.targetException?.message ?: e.message}", e.targetException ?: e)
        }
    }
    @Synchronized fun stop() {
        if (!started) return
        try { Class.forName(CLS).getMethod("TProxyStopService").invoke(null) }
        catch (e: Throwable) { JuanBus.log("TUN stop warning: ${e.cause?.message ?: e.message}") }
        finally { started = false }
    }
}

class JuanVpnService : VpnService() {
    override fun onCreate() {
        super.onCreate()
        JuanBus.init(applicationContext)
    }

    companion object { const val START = "juan.START"; const val STOP = "juan.STOP"; const val CFG = "cfg"; private const val NID = 42 }

    private var engine: TunnelEngine? = null
    private var tun: ParcelFileDescriptor? = null
    @Volatile private var tunFd = -1
    @Volatile private var worker: Thread? = null
    @Volatile private var lastWorker: Thread? = null
    private val sched = Executors.newSingleThreadScheduledExecutor()
    private var statsJob: ScheduledFuture<*>? = null
    private var t0 = 0L
    @Volatile private var stopping = false

    // Auto reconnect (airplane mode, signal loss, wifi <-> mobile data): the old tunnel is replaced by a new session.
    private val reconnecting = AtomicBoolean(false)
    @Volatile private var holdTun = false            // keep the old TUN as a blackhole until the new tunnel is ready
    @Volatile private var lastJson: String? = null
    @Volatile private var autoReconnect = true
    private var netCb: ConnectivityManager.NetworkCallback? = null
    private var airRx: BroadcastReceiver? = null
    private val nets: MutableSet<Network> = java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap<Network, Boolean>())

    override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
        if (i?.action == STOP) { stopping = true; teardown(); post("DISCONNECTED", "", ""); stopSelf(); return START_NOT_STICKY }
        val json = i?.getStringExtra(CFG) ?: run { stopSelf(); return START_NOT_STICKY }
        if (JuanBus.state == "CONNECTING" || JuanBus.state == "CONNECTED" || (!stopping && worker?.isAlive == true)) {
            JuanBus.log("Ignored duplicate connection start request")
            return START_NOT_STICKY
        }
        channel()
        ServiceCompat.startForeground(this, NID, notif("Connecting…"),
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0)
        stopping = false
        lastJson = json
        JuanDevice.networkLines(this).forEach { JuanBus.log(it) }
        // A new worker first waits for a cancelled one to finish, so two workers never run side by side.
        val prev = lastWorker
        val t = Thread {
            try {
                if (prev != null && prev.isAlive && prev !== Thread.currentThread()) prev.join(4000)
                connectFlow(json)
            } catch (_: InterruptedException) {}
        }
        t.name = "JuanConnect"
        worker = t; lastWorker = t
        t.start()
        return START_NOT_STICKY
    }

    private fun makeEngine(c: JuanCfg): TunnelEngine = when (c.tunnel) {
        "ssh" -> JuanSshEngine(c, JuanBus::log, trust()) { s -> protect(s) }
        "hy" -> JuanHyEngine(this, c, JuanBus::log)
        else -> JuanXEngine(c, JuanBus::log) { s -> protect(s) }
    }

    /**
     * Retries temporary failures (proxy 5xx such as 520, dropped handshakes, timeouts) with a growing,
     * slightly randomised pause so the proxy/CDN can release the previous half-open connection.
     * Never retries bad credentials or host-key problems.
     */
    private fun startWithRetry(c: JuanCfg): TunnelEngine? {
        val max = if (c.reconnect) c.retries.coerceIn(1, 10) + 1 else 1
        val rnd = java.util.Random()
        var attempt = 0
        while (true) {
            attempt++
            if (!live()) return null                       // a newer connect (or a disconnect) took over
            val eng = makeEngine(c)
            engine = eng
            try { eng.start(); return eng } catch (ex: Throwable) {
                eng.stop()
                // An interrupt clears the thread flag, so also check the exception and whether this is still the current worker.
                if (ex is InterruptedException || !live()) return null
                if (ex is JuanFatalException || attempt >= max || !JuanSshEngine.transient(ex)) throw ex
                val wait = minOf(1500L * attempt, c.delay * 1000L) + rnd.nextInt(600)
                JuanBus.log("Attempt $attempt failed: ${JuanSshEngine.friendly(ex.cause ?: ex)} Retrying in ${"%.1f".format(wait / 1000.0)}s…")
                post("CONNECTING", "Retrying ($attempt/${max - 1})", "")
                Thread.sleep(wait)
            }
        }
    }

    /** True while this is still the current worker and nobody asked to disconnect. */
    private fun live() = !stopping && Thread.currentThread() === worker && !Thread.currentThread().isInterrupted

    /** One full connection attempt. Returns null when it finished (connected or cancelled), otherwise the failure. */
    private fun connectOnce(json: String, announce: Boolean): Throwable? = try {
        if (announce) JuanBus.log("Connection worker started")
        val c = JuanPolicy.apply(this, JuanCfg.parse(json))
        autoReconnect = c.reconnect
        JuanPolicy.check(this, c)?.let { throw IllegalStateException(it) }
        c.validate()?.let { throw IllegalArgumentException(it) }
        if (live()) {
            if (announce) post("CONNECTING", when (c.tunnel) { "smart" -> "Choosing the best route"; "hy" -> "Opening Hysteria tunnel"; "dnstt", "dnsv2" -> "Opening DNS tunnel"; "ssh" -> "Opening SSH tunnel"; "ss" -> "Opening Shadowsocks tunnel"; else -> "Opening ${c.xProto.uppercase()} tunnel" }, "")
            when (c.tunnel) { "smart" -> smartAuto(c); "ssh" -> smartConnect(c); "dnstt", "dnsv2" -> dnsConnect(c); else -> legacyConnect(c) }
        }
        null
    } catch (ex: Throwable) { ex }

    @Volatile private var lastDown = 0L

    private fun connectFlow(json: String) {
        val gap = 7000L - (System.currentTimeMillis() - lastDown)
        if (gap in 1..7000) { JuanBus.log("Preparing connection..."); try { Thread.sleep(gap) } catch (_: InterruptedException) { return } }
        val ex = connectOnce(json, true) ?: return
        if (!live()) return
        val msg = if (ex is JuanFatalException) (ex.message ?: "Connection failed") else JuanSshEngine.friendly(JuanRotation.rootCause(ex))
        JuanBus.log("Error: $msg")
        teardown(); post("ERROR", "", msg); stopSelf()
    }

    /* ------------------------------------------------------------ auto reconnect */

    private fun registerMonitor() {
        if (netCb != null) return
        try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
            nets.clear()
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    val wasEmpty = nets.isEmpty()
                    nets.add(network)
                    if (wasEmpty && JuanBus.state != "DISCONNECTED") JuanBus.log("Network: back online")
                }
                override fun onLost(network: Network) {
                    nets.remove(network)
                    if (nets.isEmpty() && !stopping) {
                        JuanBus.log("Network: lost (airplane mode or no signal)")
                        if (JuanBus.state == "CONNECTED") beginReconnect("network lost")
                    }
                }
            }
            cm.registerNetworkCallback(req, cb)
            netCb = cb
            val rx = object : BroadcastReceiver() {
                override fun onReceive(c: Context, i: Intent) { JuanBus.log("Airplane mode: " + if (i.getBooleanExtra("state", false)) "ON" else "OFF") }
            }
            val f = IntentFilter(Intent.ACTION_AIRPLANE_MODE_CHANGED)
            if (Build.VERSION.SDK_INT >= 33) registerReceiver(rx, f, Context.RECEIVER_NOT_EXPORTED) else registerReceiver(rx, f)
            airRx = rx
        } catch (e: Throwable) { JuanBus.log("Network monitor unavailable: ${e.message}") }
    }

    private fun unregisterMonitor() {
        try { netCb?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } } catch (_: Throwable) {}
        netCb = null
        try { airRx?.let { unregisterReceiver(it) } } catch (_: Throwable) {}
        airRx = null
        nets.clear()
    }

    /** Replaces the tunnel with a fresh session. The old TUN stays up (blocking traffic) so nothing leaks while waiting. */
    private fun beginReconnect(reason: String) {
        if (stopping || !autoReconnect) return
        val json = lastJson ?: return
        if (!reconnecting.compareAndSet(false, true)) return
        JuanBus.log("Reconnect: $reason")
        holdTun = true
        post("CONNECTING", if (nets.isEmpty()) "Waiting for network" else "Reconnecting", "")
        val old = worker
        val t = Thread {
            try { reconnectLoop(json) } catch (_: InterruptedException) {} finally { reconnecting.set(false) }
        }
        t.name = "JuanReconnect"
        worker = t; lastWorker = t
        if (old != null && old !== Thread.currentThread()) old.interrupt()
        t.start()
    }

    private fun reconnectLoop(json: String) {
        statsJob?.cancel(false); statsJob = null
        try { engine?.stop() } catch (_: Exception) {}
        engine = null
        val max = 6
        var attempt = 0
        while (live() && attempt < max) {
            if (nets.isEmpty()) {
                post("CONNECTING", "Waiting for network", "")
                if (!awaitNetwork(10 * 60_000L)) break
                JuanBus.log("Network: ready, reconnecting")
                JuanDevice.networkLines(this).forEach { JuanBus.log(it) }
                Thread.sleep(2500)                 // the radio needs a moment after airplane mode
                post("CONNECTING", "Reconnecting", "")
            }
            attempt++
            JuanBus.log("Reconnect: attempt $attempt/$max")
            val ex = connectOnce(json, false)
            if (!live()) return
            if (JuanBus.state == "CONNECTED") { JuanBus.log("Reconnect: connected again"); return }
            JuanBus.log("Reconnect: failed - " + JuanSshEngine.friendly(JuanRotation.rootCause(ex ?: RuntimeException("No connection"))))
            if (ex is JuanFatalException) break
            Thread.sleep(minOf(3000L * attempt, 15000L))
        }
        if (live()) {
            JuanBus.log("Reconnect: giving up")
            teardown(); post("ERROR", "", "Could not reconnect after the network changed"); stopSelf()
        }
    }

    /** Looks up the exit IP through the tunnel and logs it; after a reconnect it says whether the IP changed. */
    private fun fetchExitIp(port: Int) {
        val prev = JuanBus.publicIp
        for (n in 1..4) {
            if (stopping || JuanBus.state != "CONNECTED") return
            val ip = JuanIp.viaSocks(port)
            if (ip != null) {
                JuanBus.publicIp = ip
                JuanBus.log("Public IP: $ip" + if (prev.isNotEmpty() && prev != ip) "  (changed from $prev)" else if (prev.isNotEmpty()) "  (same as before)" else "")
                return
            }
            try { Thread.sleep(2000) } catch (_: InterruptedException) { return }
        }
        JuanBus.log("Public IP: could not be detected")
    }

    private fun awaitNetwork(maxMs: Long): Boolean {
        val end = System.currentTimeMillis() + maxMs
        while (live()) {
            if (nets.isNotEmpty()) return true
            if (System.currentTimeMillis() > end) return false
            Thread.sleep(500)
        }
        return false
    }

    /** Shadowsocks / V2Ray profiles: no proxy combinations to rotate, so the original retry loop is kept. */
    @Volatile private var fastFail = false
    @Volatile private var aux: java.io.Closeable? = null
    @Volatile private var aux2: java.io.Closeable? = null

    /**
     * SlowDNS / DNSTT. The DNSTT program carries one TCP connection inside DNS queries and offers it on a local port.
     * SSH (or V2Ray / Shadowsocks) then connects to that local port instead of the real server.
     */
    private fun dnsConnect(c: JuanCfg) {
        try { aux2?.close() } catch (_: Exception) {}; aux2 = null
        try { aux?.close() } catch (_: Exception) {}
        val runner = JuanDnsttRunner(this, c, JuanBus::log)
        aux = runner
        val port = runner.start()
        if (!live()) return
        if (c.tunnel == "dnstt") {
            smartConnect(c.copy(tunnel = "ssh", from = "direct", custom = false, sshHost = "127.0.0.1", sshPort = port,
                pHost = "", payload = "", proxies = emptyList(), snis = emptyList(), payloads = emptyList()))
        } else {
            val x = c.copy(tunnel = if (c.xProto == "ss") "ss" else "v2", xSni = c.xSni.ifBlank { c.xHost }, xWsHost = c.xWsHost.ifBlank { c.xHost })
            // Most DNS tunnel servers forward to SSH, not to V2Ray. With an SSH login filled in, V2Ray / Shadowsocks goes
            // inside SSH (DNS -> SSH -> V2Ray). Without one, or if SSH is refused, it is tried straight through DNS.
            val sshReady = c.user.isNotBlank() && (c.pass.isNotEmpty() || c.key.isNotBlank()) && c.xHost.isNotBlank()
            if (sshReady) {
                var ssh: JuanSshEngine? = null
                try {
                    val sc = c.copy(tunnel = "ssh", from = "direct", custom = false, sshHost = "127.0.0.1", sshPort = port,
                        pHost = "", payload = "", proxies = emptyList(), snis = emptyList(), payloads = emptyList())
                    JuanBus.log("Connecting...")
                    val eng = makeEngine(sc) as JuanSshEngine
                    ssh = eng
                    eng.start()
                    if (!live()) { eng.stop(); return }
                    aux2 = java.io.Closeable { eng.stop() }
                    val lp = eng.forwardTo(c.xHost, c.xPort)
                    legacyConnect(x.copy(xHost = "127.0.0.1", xPort = lp))
                    return
                } catch (ex: Throwable) {
                    try { ssh?.stop() } catch (_: Exception) {}
                    try { aux2?.close() } catch (_: Exception) {}; aux2 = null
                    if (ex is InterruptedException || !live()) return
                    abortAttempt()
                    JuanBus.log("Trying the direct route...")
                }
            }
            legacyConnect(x.copy(xHost = "127.0.0.1", xPort = port))
        }
    }

    /**
     * Smart profile. Tries the SSH route (with all its proxy / SNI / payload combinations) and the V2Ray / Shadowsocks
     * route. The one that worked last goes first. When a route fails the next one starts straight away, and if all
     * of them fail the user gets one clear message.
     */
    private fun smartAuto(c: JuanCfg) {
        val routes = listOfNotNull(c.sshVariant()?.let { "ssh" to it }, c.xVariant()?.let { "x" to it }, c.hyVariant()?.let { "hy" to it })
        if (routes.isEmpty()) throw JuanFatalException("Add an SSH, V2Ray / Shadowsocks or Hysteria server")
        val sp = getSharedPreferences("juan_smart", Context.MODE_PRIVATE)
        val key = "last_" + (c.sshHost + "|" + c.xHost + "|" + c.hyHost).hashCode()
        val last = sp.getString(key, "") ?: ""
        val order = routes.sortedBy { if (it.first == last) 0 else 1 }
        var lastErr: Throwable? = null
        try {
            for ((i, r) in order.withIndex()) {
                if (!live()) return
                val more = i < order.size - 1
                fastFail = more                                   // move on quickly while another route is left
                JuanBus.log(if (i == 0) "Connecting..." else "Trying another route...")
                val cfg = if (more) r.second.copy(retries = minOf(r.second.retries, 1)) else r.second
                try {
                    if (r.first == "ssh") smartConnect(cfg) else legacyConnect(cfg)
                    if (JuanBus.state == "CONNECTED") { sp.edit().putString(key, r.first).apply(); return }
                    if (!live()) return
                } catch (ex: Throwable) {
                    if (!live()) return
                    abortAttempt()
                    lastErr = ex
                    JuanBus.log("Connection attempt failed.")
                    JuanBus.log("Reason: " + JuanSshEngine.friendly(JuanRotation.rootCause(ex)))
                }
            }
        } finally { fastFail = false }
        throw JuanFatalException("Could not connect. Last error: " + (lastErr?.let { JuanSshEngine.friendly(JuanRotation.rootCause(it)) } ?: "no route worked"))
    }

    private fun legacyConnect(c: JuanCfg) {
        val e = startWithRetry(c) ?: return
        if (!live()) { e.stop(); return }
        bringUp(c, e)
        finishConnected(c, e)
    }

    /**
     * SSH profiles. Every proxy x SNI x payload combination is one candidate. The last successful one goes first;
     * each candidate is tried once per cycle, a whole cycle that fails is followed by a pause and a new cycle.
     * A combination only counts as working after TCP, WebSocket/HTTP, SSH banner, SSH login, TUN and the traffic check.
     */
    private fun smartConnect(c: JuanCfg) {
        val plan = JuanRotation.plan(c)
        if (plan.combos.isEmpty())
            throw JuanFatalException("No usable connection settings. Check the proxy, SNI and payload.")
        val (order, prevNo) = JuanRotation.order(plan.combos, JuanRotation.loadPreferred(this, c))
        val total = order.size
        val cycles = if (c.reconnect) c.retries.coerceIn(1, 10) + 1 else 1
        val rnd = java.util.Random()
        var last = ""
        for (cycle in 1..cycles) {
            for ((n, k) in order.withIndex()) {
                if (!live()) return
                val preferred = prevNo > 0 && n == 0
                JuanBus.log(if (n == 0 && cycle == 1) "Connecting..." else "Retrying connection...")
                logCombo(c, k)
                var ex = tryCombo(c, k, preferred) ?: return          // null = connected
                if (!live()) return
                // A login refused right after a disconnect is often the server still holding the old session (or rate
                // limiting quick retries). Give it a moment and try the same login again before calling it wrong.
                var authTry = 0
                while (live() && !fastFail && authTry < 2 && JuanRotation.classify(ex) == JuanFail.SSH_AUTH) {
                    authTry++
                    JuanBus.log("Server is busy, retrying...")
                    post("CONNECTING", "Retrying", "")
                    try { Thread.sleep(3500L * authTry) } catch (_: InterruptedException) { return }
                    if (!live()) return
                    ex = tryCombo(c, k, preferred) ?: return
                    if (!live()) return
                }
                val kind = JuanRotation.classify(ex)
                val why = JuanSshEngine.friendly(JuanRotation.rootCause(ex))
                JuanBus.log("Connection attempt failed.")
                JuanBus.log("Reason: ${kind.label} - $why")
                last = "${kind.label} - $why"
                if (!JuanRotation.shouldRotate(ex)) throw ex            // bad login, host key, fatal setup: another combination cannot help
            }
            if (cycle < cycles) {
                val wait = minOf(1500L * cycle, c.delay * 1000L) + rnd.nextInt(600)
                JuanBus.log("Could not connect. Retrying in ${"%.0f".format(wait / 1000.0)}s...")
                post("CONNECTING", "Retrying ($cycle/${cycles - 1})", "")
                Thread.sleep(wait)
            }
        }
        throw JuanFatalException("Could not connect. Last error: $last")
    }

    private fun logCombo(c: JuanCfg, k: JuanRotation.Combo) {
        JuanBus.log("Proxy: ${k.proxyLabel}" +
                        " | Mode: ${c.from}")
    }

    /** One combination, start to finish. Returns null when connected, otherwise what went wrong (everything already cleaned up). */
    private fun tryCombo(c: JuanCfg, k: JuanRotation.Combo, preferred: Boolean): Throwable? {
        if (!live()) return JuanConnException(JuanFail.CANCELLED, "Cancelled by user")
        val pc = JuanRotation.pin(c, k)
        val eng = makeEngine(pc)
        engine = eng
        return try {
            eng.start()                                   // TCP, WebSocket/HTTP, SSH banner, SSH login
            if (!live()) throw JuanConnException(JuanFail.CANCELLED, "Cancelled by user")
            bringUp(pc, eng)                              // TUN + traffic check
            if (!live()) throw JuanConnException(JuanFail.CANCELLED, "Cancelled by user")
                        JuanRotation.savePreferred(this, c, k)
            finishConnected(pc, eng)
            null
        } catch (ex: Throwable) {
            abortAttempt()
            ex
        }
    }

    /** Starts the packet engine on a tunnel that is already open and proves traffic passes. Throws the stage that failed. */
    private fun bringUp(c: JuanCfg, e: TunnelEngine) {
        post("CONNECTING", "Starting TUN", "")
        if (holdTun) { TunEngine.stop(); closeTun(); holdTun = false }   // swap the old (blackhole) TUN for the new one
        val pfd = try { build(c) } catch (ex: IllegalStateException) { throw JuanFatalException(ex.message ?: "VPN setup failed") }
            ?: throw JuanFatalException("VPN permission missing or revoked")
        tunFd = pfd.detachFd()   // native code may close it; Java must not double-close (fdsan)
        if (!live()) throw JuanConnException(JuanFail.CANCELLED, "Cancelled by user")
        JuanBus.log("TUN: interface up, starting native engine")
        try { TunEngine.start(this, tunFd, e.socksPort, c.tunnel == "hy") } catch (ex: IllegalStateException) {
            if (ex.message?.contains("not bundled") == true) throw JuanFatalException(ex.message ?: "TUN engine missing")
            throw JuanConnException(JuanFail.TUN_INIT, ex.message ?: "TUN engine failed to start", ex)
        }
        Thread.sleep(700)
        if (!tunIsOpen(tunFd)) throw JuanConnException(JuanFail.TUN_INIT, "The TUN engine stopped right after starting. Open Log and tap Native log for details.")
        JuanBus.log("TUN: STARTED")
        post("CONNECTING", "Checking tunnel", "")
        JuanBus.log("Traffic: running check")
        if (!e.probe()) throw JuanConnException(JuanFail.TRAFFIC, e.probeError.ifBlank { "The tunnel is up but no traffic passed through it" })
        JuanBus.log("Traffic: CHECK PASSED")
    }

    /** Only called after every stage (including the traffic check) passed. */
    private fun finishConnected(c: JuanCfg, e: TunnelEngine) {
        t0 = System.currentTimeMillis()
        post("CONNECTED", when (c.tunnel) { "ssh" -> "SSH tunnel active"; "hy" -> "Hysteria tunnel active"; else -> "${c.xProto.uppercase()} tunnel active" }, "")
        startStats(e)
        registerMonitor()
        JuanBus.socksPort = e.socksPort
        val port = e.socksPort
        Thread { fetchExitIp(port) }.also { it.name = "JuanIp" }.start()
        startPing(port)
    }

    private val pingGen = java.util.concurrent.atomic.AtomicInteger()

    /** Pings through the tunnel every few seconds while connected. The Settings switch can turn it on or off at any time. */
    private fun startPing(port: Int) {
        val gen = pingGen.incrementAndGet()
        JuanBus.pingMs = -2
        Thread {
            try { Thread.sleep(2500) } catch (_: InterruptedException) { return@Thread }
            while (gen == pingGen.get() && !stopping && JuanBus.state == "CONNECTED") {
                if (JuanBus.pingOn) {
                    try {
                        val (code, ms) = JuanPing.viaSocks(port, JuanBus.pingUrl)
                        if (gen != pingGen.get()) return@Thread
                        JuanBus.pingMs = ms
                        JuanBus.logLive("Ping: $code (${ms}ms)")
                    } catch (_: InterruptedException) { return@Thread }
                    catch (e: Exception) {
                        if (gen != pingGen.get()) return@Thread
                        JuanBus.pingMs = -1
                        JuanBus.logLive("Ping: failed (" + (if (e is java.net.SocketTimeoutException) "timeout" else "no response") + ")")
                    }
                } else JuanBus.pingMs = -2
                try { Thread.sleep(5000) } catch (_: InterruptedException) { return@Thread }
            }
        }.also { it.name = "JuanPing"; it.isDaemon = true }.start()
    }

    /** Undo whatever a failed attempt got as far as starting (TUN, packet engine, SSH session, half-open sockets). */
    private fun abortAttempt() {
        if (!holdTun) {
            try { TunEngine.stop() } catch (_: Throwable) {}
            closeTun()
        }
        try { engine?.stop() } catch (_: Exception) {}
        engine = null
    }

    private fun build(c: JuanCfg): ParcelFileDescriptor? {
        val b = Builder().setSession("JUAN VPN").setMtu(1500)
            .addAddress("10.10.10.2", 32).addRoute("0.0.0.0", 0).addDnsServer(TunEngine.DNS)
            .addAddress("fd00:10:10::2", 128).addRoute("::", 0) // IPv6 blackholed: no leaks, tunnel is IPv4-only
        if (c.policy?.optBoolean("gamingMode", false) == true) {
            val games = JuanPolicy.gamePackages(this)
            if (games.isEmpty()) throw IllegalStateException("Gaming mode: no installed games were found on this phone")
            JuanBus.log("Gaming mode: only ${games.size} game app(s) use the VPN")
            games.forEach { try { b.addAllowedApplication(it) } catch (_: Exception) {} }
        } else when (c.appMode) {
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

    private fun startStats(e: TunnelEngine) {
        var lu = 0L; var ld = 0L
        statsJob = sched.scheduleAtFixedRate({
            val u = e.up.get(); val d = e.down.get()
            JuanBus.onStats?.invoke(JSONObject().put("up", u).put("down", d).put("upBps", u - lu).put("downBps", d - ld).put("ip", JuanBus.publicIp).put("ping", JuanBus.pingMs)
                .put("uptime", (System.currentTimeMillis() - t0) / 1000))
            lu = u; ld = d
            if (!e.alive() && !stopping && !reconnecting.get()) {
                JuanBus.log("Tunnel: connection lost")
                if (autoReconnect && lastJson != null) beginReconnect("connection lost")
                else { teardown(); post("ERROR", "", "Tunnel connection dropped"); stopSelf() }
            }
        }, 1, 1, TimeUnit.SECONDS)
    }

    private fun post(s: String, d: String, e: String) {
        JuanBus.state = s; JuanBus.detail = d; JuanBus.error = e
        if (s == "DISCONNECTED" || s == "ERROR") { JuanBus.publicIp = ""; JuanBus.socksPort = 0; JuanBus.pingMs = -2 }
        JuanBus.log("State: $s${if (d.isNotEmpty()) " ($d)" else ""}")
        JuanBus.onState?.invoke(s, d, e)
        val safeNotification = when (s) {
            "CONNECTED" -> "Connected · VPN active"
            "CONNECTING" -> when {
                d.contains("Waiting for network", ignoreCase = true) -> "Waiting for network…"
                d.contains("retry", ignoreCase = true) || d.contains("reconnect", ignoreCase = true) -> "Reconnecting…"
                d.contains("SSH", ignoreCase = true) -> "Connecting · SSH"
                d.contains("VMESS", ignoreCase = true) -> "Connecting · VMess"
                d.contains("VLESS", ignoreCase = true) -> "Connecting · VLESS"
                d.contains("TROJAN", ignoreCase = true) -> "Connecting · Trojan"
                d.contains("Shadowsocks", ignoreCase = true) -> "Connecting · Shadowsocks"
                d.contains("TUN", ignoreCase = true) -> "Starting secure tunnel…"
                d.contains("Checking", ignoreCase = true) -> "Checking connection…"
                else -> "Connecting…"
            }
            "ERROR" -> "Connection failed · Open JUAN VPN logs"
            "DISCONNECTED" -> "Disconnected"
            else -> "VPN status updated"
        }
        getSystemService(NotificationManager::class.java).notify(NID, notif(safeNotification))
    }

    private fun tunIsOpen(fd: Int): Boolean = fd >= 0 && try {
        android.system.Os.readlink("/proc/self/fd/$fd").contains("tun")
    } catch (_: Throwable) { false }

    private fun closeTun() {
        val fd = tunFd; tunFd = -1
        if (tunIsOpen(fd)) try { ParcelFileDescriptor.adoptFd(fd).close() } catch (_: Throwable) {}
    }

    @Synchronized private fun teardown() {
        lastDown = System.currentTimeMillis()
        try { aux2?.close() } catch (_: Exception) {}; aux2 = null
        try { aux?.close() } catch (_: Exception) {}; aux = null
        stopping = true
        holdTun = false
        unregisterMonitor()
        pingGen.incrementAndGet()
        statsJob?.cancel(true); statsJob = null
        // Stop the native engine only after a successful native start.
        TunEngine.stop()
        closeTun()
        try { engine?.stop() } catch (e: Exception) { JuanBus.log("SSH cleanup warning: ${e.message}") }
        engine = null
        worker?.takeIf { it !== Thread.currentThread() }?.interrupt()
        worker = null
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
