package com.juanvpn.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.content.FileProvider
import java.io.File
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import org.json.JSONArray
import org.json.JSONObject

class JuanWebActivity : Activity() {
    private lateinit var web: WebView
    private var sent = 0
    private var pending: String? = null
    private var exportText: String? = null
    private val exportQueue = ArrayDeque<Pair<String, String>>()
    private var waitingForNotification = false
    private var connectionRequestInFlight = false

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        JuanBus.init(applicationContext)
        JuanCrash.install(this)
        JuanCrash.report(this)?.let { JuanBus.log(it) }
        val lastLine = synchronized(JuanBus.logs) { JuanBus.logs.lastOrNull().orEmpty() }
        if (lastLine.contains("TUN") || lastLine.contains("Checking tunnel"))
            Thread { JuanBus.log("Native log from the last run:\n" + JuanCrash.nativeTail()) }.start()
        web = WebView(this).apply {
            setBackgroundColor(0xff0a111f.toInt())
            settings.javaScriptEnabled = true; settings.domStorageEnabled = true
            settings.allowContentAccess = false
            addJavascriptInterface(Bridge(), "JuanBridge")
            loadUrl("file:///android_asset/juanvpn-ui.html")
        }
        val root = android.widget.FrameLayout(this).apply { setBackgroundColor(0xff0d1730.toInt()) }
        root.addView(web, android.widget.FrameLayout.LayoutParams(-1, -1))
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, i ->
            val s = i.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime())
            v.setPadding(s.left, s.top, s.right, s.bottom); WindowInsetsCompat.CONSUMED
        }
        WindowCompat.getInsetsController(window, root).isAppearanceLightStatusBars = false
        setContentView(root)
        ViewCompat.requestApplyInsets(root)
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() { web.evaluateJavascript("JuanUI.back()") { r -> if (r != "true") finish() } }

    private fun js(code: String) = runOnUiThread { web.evaluateJavascript(code, null) }
    private fun q(s: String?) = JSONObject.quote(s ?: "")

    override fun onResume() {
        super.onResume()
        JuanBus.onState = { s, d, e ->
            if (s == "CONNECTED" || s == "ERROR" || s == "DISCONNECTED") connectionRequestInFlight = false
            js("JuanUI.setState(${q(s)},${q(d)},${q(e)})")
        }
        JuanBus.onLog = { l -> synchronized(this) { sent++ }; js("JuanUI.log(${q(l)})") }
        JuanBus.onStats = { o -> js("JuanUI.stats($o)") }
        JuanBus.onHostKey = { h, t, f -> js("JuanUI.hostKey(${q(h)},${q(t)},${q(f)})") }
        web.postDelayed({
            val snap = synchronized(JuanBus.logs) { JuanBus.logs.toList() }
            val from = synchronized(this) { val f = sent.coerceAtMost(snap.size); sent = snap.size; f }
            snap.drop(from).forEach { js("JuanUI.log(${q(it)})") }
            JuanBus.pendingHK?.let { js("JuanUI.hostKey(${q(it.first)},${q(it.second)},${q(it.third)})") }
            if (JuanBus.state != "DISCONNECTED") js("JuanUI.setState(${q(JuanBus.state)},${q(JuanBus.detail)},${q(JuanBus.error)})")
        }, 400)
    }

    override fun onPause() { JuanBus.onState = null; JuanBus.onLog = null; JuanBus.onStats = null; JuanBus.onHostKey = null; super.onPause() }

    private fun startNextExport() {
        if (exportQueue.isEmpty()) { exportText = null; return }
        val (name, text) = exportQueue.removeFirst()
        exportText = text
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, name), 701)
    }

    private fun startVpn(json: String) {
        try {
            ContextCompat.startForegroundService(this,
                Intent(this, JuanVpnService::class.java).setAction(JuanVpnService.START).putExtra(JuanVpnService.CFG, json))
        } catch (e: Exception) {
            connectionRequestInFlight = false
            val message = "Could not start VPN service: ${e.message ?: e.javaClass.simpleName}"
            JuanBus.log(message)
            js("JuanUI.setState('ERROR','',${q(message)})")
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        super.onActivityResult(req, res, data)
        when (req) {
            700 -> {
                val p = pending
                pending = null
                connectionRequestInFlight = false
                if (res == RESULT_OK && p != null) startVpn(p)
                else js("JuanUI.setState('ERROR','',${q("VPN permission was denied")})")
            }
            701 -> {
                val target = data?.data
                val text = exportText
                exportText = null
                if (target != null && text != null) {
                    try { contentResolver.openOutputStream(target)?.use { it.write(text.toByteArray(Charsets.UTF_8)) } }
                    catch (e: Exception) { JuanBus.log("HJ save failed: ${e.message}") }
                    startNextExport()
                } else exportQueue.clear()
            }
            702 -> data?.data?.let { uri ->
                try {
                    val text = contentResolver.openInputStream(uri)?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
                        ?: throw IllegalStateException("Could not read selected config")
                    require(text.length <= 2_000_000) { "Config file is too large" }
                    js("JuanUI.importFile(${q(text)})")
                } catch (e: Exception) { JuanBus.log("HJ import failed: ${e.message}"); js("JuanUI.importError(${q(e.message)})") }
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 703 && waitingForNotification) {
            waitingForNotification = false
            continueVpnPermissionFlow()
        }
    }

    private fun continueVpnPermissionFlow() {
        val p = pending ?: return
        try {
            val consent = VpnService.prepare(this)
            if (consent == null) {
                pending = null
                startVpn(p)
            } else {
                startActivityForResult(consent, 700)
            }
        } catch (e: Exception) {
            pending = null
            connectionRequestInFlight = false
            val message = "Unable to request VPN permission: ${e.message ?: e.javaClass.simpleName}"
            JuanBus.log(message)
            js("JuanUI.setState('ERROR','',${q(message)})")
        }
    }

    inner class Bridge {
        @JavascriptInterface fun connect(json: String) = runOnUiThread {
            if (connectionRequestInFlight || JuanBus.state == "CONNECTING" || JuanBus.state == "CONNECTED") {
                js("JuanUI.log('A connection request is already active.')")
                return@runOnUiThread
            }
            connectionRequestInFlight = true
            pending = json
            if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
                waitingForNotification = true
                requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 703)
                return@runOnUiThread
            }
            continueVpnPermissionFlow()
        }
        @JavascriptInterface fun saveSecrets(j: String) { JuanSecrets.save(applicationContext, j) }
        @JavascriptInterface fun forgetHostKey(host: String, port: String) {
            val label = if (port == "22") host else "[$host]:$port"
            getSharedPreferences("juan_trust", MODE_PRIVATE).edit().remove(label).apply()
        }
        @JavascriptInterface fun appendUiLog(message: String) { JuanBus.addSilent(message); synchronized(this@JuanWebActivity) { sent++ } }
        @JavascriptInterface fun nativeLog() { Thread { JuanBus.log("Native log:\n" + JuanCrash.nativeTail()) }.start() }
        @JavascriptInterface fun clearLogs() {
            AppLog.clear(applicationContext); synchronized(JuanBus.logs) { JuanBus.logs.clear() }
            synchronized(this@JuanWebActivity) { sent = 0 }
        }
        @JavascriptInterface fun readLogs(): String = AppLog.read(applicationContext)
        @JavascriptInterface fun loadSecrets(): String = JuanSecrets.load(applicationContext)
        @JavascriptInterface fun hostKeyAnswer(ok: Boolean) { JuanBus.answer = ok; JuanBus.latch?.countDown() }
        @JavascriptInterface fun disconnect() {
            connectionRequestInFlight = false
            pending = null
            startService(Intent(this@JuanWebActivity, JuanVpnService::class.java).setAction(JuanVpnService.STOP))
        }
        @JavascriptInterface fun notifPerm() = runOnUiThread {
            if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 703)
        }
        @JavascriptInterface fun batteryHelp() = runOnUiThread { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
        @JavascriptInterface fun chooseImport() = runOnUiThread {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION), 702)
        }
        @JavascriptInterface fun exportFile(name: String, text: String) = runOnUiThread {
            exportQueue.clear(); exportQueue.add(name to text); startNextExport()
        }
        @JavascriptInterface fun exportFiles(name1: String, text1: String, name2: String, text2: String) = runOnUiThread {
            exportQueue.clear(); exportQueue.add(name1 to text1); exportQueue.add(name2 to text2); startNextExport()
        }
        @JavascriptInterface fun makeHJ(config: String, password: String): String = try {
            HJConfig.encrypt(config, password)
        } catch (e: Exception) { "ERROR:${e.message ?: "Could not encrypt HJ config"}" }
        @JavascriptInterface fun makeUnlockedHJ(config: String): String = try {
            HJConfig.unlocked(config)
        } catch (e: Exception) { "ERROR:${e.message ?: "Could not create HJ config"}" }
        @JavascriptInterface fun openHJ(text: String, password: String): String = try {
            val box = JSONObject(text)
            if (box.optBoolean("locked", false)) HJConfig.decrypt(text, password) else HJConfig.open(text)
        } catch (e: Exception) { "ERROR:${e.message ?: "Could not open HJ config"}" }
        @JavascriptInterface fun shareFile(name: String, text: String) = runOnUiThread {
            try {
                val dir = File(cacheDir, "exports").apply { mkdirs() }
                val file = File(dir, name.replace(Regex("[^A-Za-z0-9._-]"), "_")).apply { writeText(text, Charsets.UTF_8) }
                val uri = FileProvider.getUriForFile(this@JuanWebActivity, "$packageName.files", file)
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "application/octet-stream"; putExtra(Intent.EXTRA_STREAM, uri)
                    clipData = android.content.ClipData.newUri(contentResolver, file.name, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                startActivity(Intent.createChooser(send, "Share JUAN HJ config"))
            } catch (e: Exception) { JuanBus.log("Share failed: ${e.message}") }
        }
        @JavascriptInterface fun listApps() { Thread {
            val pm = packageManager
            val l = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
                .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
                .filter { it.first != packageName }.distinctBy { it.first }.sortedBy { it.second.lowercase() }
            val a = JSONArray(); l.forEach { a.put(JSONObject().put("pkg", it.first).put("name", it.second)) }
            js("JuanUI.apps($a)") }.start() }
        @JavascriptInterface fun tool(name: String, json: String) { Thread {
            js("JuanUI.toolResult(${q(JuanTools.run(name, JSONObject(json)))})") }.start() }
    }
}
