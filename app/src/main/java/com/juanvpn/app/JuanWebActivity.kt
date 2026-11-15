package com.juanvpn.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
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
    private var pending: String? = null
    private var exportText: String? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
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
        JuanBus.onState = { s, d, e -> js("JuanUI.setState(${q(s)},${q(d)},${q(e)})") }
        JuanBus.onLog = { l -> js("JuanUI.log(${q(l)})") }
        JuanBus.onStats = { o -> js("JuanUI.stats($o)") }
        web.postDelayed({
            JuanBus.logs.toList().forEach { js("JuanUI.log(${q(it)})") }
            if (JuanBus.state != "DISCONNECTED") js("JuanUI.setState(${q(JuanBus.state)},${q(JuanBus.detail)},${q(JuanBus.error)})")
        }, 400)
    }

    override fun onPause() { JuanBus.onState = null; JuanBus.onLog = null; JuanBus.onStats = null; super.onPause() }

    private fun startVpn(json: String) = ContextCompat.startForegroundService(this,
        Intent(this, JuanVpnService::class.java).setAction(JuanVpnService.START).putExtra(JuanVpnService.CFG, json))

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        super.onActivityResult(req, res, data)
        when (req) {
            700 -> { val p = pending; pending = null
                if (res == RESULT_OK && p != null) startVpn(p)
                else js("JuanUI.setState('ERROR','',${q("VPN permission was denied")})") }
            701 -> data?.data?.let { u -> exportText?.let { t -> contentResolver.openOutputStream(u)?.use { it.write(t.toByteArray()) } } }
        }
    }

    inner class Bridge {
        @JavascriptInterface fun connect(json: String) = runOnUiThread {
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED)
                requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 703)
            val i = VpnService.prepare(this@JuanWebActivity)
            if (i == null) startVpn(json) else { pending = json; startActivityForResult(i, 700) }
        }
        @JavascriptInterface fun saveSecrets(j: String) { JuanSecrets.save(applicationContext, j) }
        @JavascriptInterface fun loadSecrets(): String = JuanSecrets.load(applicationContext)
        @JavascriptInterface fun disconnect() { startService(Intent(this@JuanWebActivity, JuanVpnService::class.java).setAction(JuanVpnService.STOP)) }
        @JavascriptInterface fun notifPerm() = runOnUiThread {
            if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 703)
        }
        @JavascriptInterface fun batteryHelp() = runOnUiThread { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
        @JavascriptInterface fun exportFile(name: String, text: String) = runOnUiThread {
            exportText = text
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*").putExtra(Intent.EXTRA_TITLE, name), 701)
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
