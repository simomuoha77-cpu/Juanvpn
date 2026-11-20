package com.juanvpn.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var store: ProfileStore
    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private lateinit var name: EditText
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var key: EditText
    private lateinit var knownHosts: EditText
    private lateinit var proxyHost: EditText
    private lateinit var proxyPort: EditText
    private lateinit var sni: EditText
    private lateinit var mode: Spinner
    private lateinit var proxyType: Spinner
    private lateinit var tls: CheckBox
    private lateinit var logView: TextView
    private var activeTab = "HOME"
    private val pickExport = 701
    private val pickImport = 702
    private val vpnRequest = 700

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ProfileStore(this)
        buildShell()
        showTab("HOME")
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 703)
        }
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
        if (activeTab == "LOGS") refreshLogs()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun buildShell() {
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xff0d1320.toInt())
        }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(20), dp(22), dp(14))
            setBackgroundColor(0xff101a2a.toInt())
        }
        header.addView(TextView(this).apply {
            text = "JUAN VPN"
            textSize = 28f
            setTextColor(0xffffffff.toInt())
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        })
        header.addView(TextView(this).apply {
            text = "SECURE CONNECTION CLIENT  ·  v1.1.0"
            textSize = 11f
            setTextColor(0xff23d5ab.toInt())
        })
        page.addView(header)
        val nav = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(8), dp(8), dp(8), dp(8))
            setBackgroundColor(0xff101a2a.toInt())
        }
        listOf("HOME", "LOGS", "TOOLS", "HELP").forEach { tab ->
            nav.addView(Button(this).apply {
                text = tab
                textSize = 11f
                isAllCaps = false
                setTextColor(0xffffffff.toInt())
                setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xff24344b.toInt()))
                layoutParams = LinearLayout.LayoutParams(0, dp(44), 1f).apply { setMargins(dp(3), 0, dp(3), 0) }
                setOnClickListener { showTab(tab) }
            })
        }
        page.addView(nav)
        val scroll = ScrollView(this)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(16), dp(18), dp(24))
        }
        scroll.addView(content)
        page.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(page)
    }

    private fun showTab(tab: String) {
        activeTab = tab
        content.removeAllViews()
        when (tab) {
            "HOME" -> buildHome()
            "LOGS" -> buildLogs()
            "TOOLS" -> buildTools()
            else -> buildHelp()
        }
    }

    private fun label(text: String) {
        content.addView(TextView(this).apply {
            this.text = text
            textSize = 12f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setTextColor(0xff9eacc2.toInt())
            setPadding(0, dp(12), 0, dp(4))
        })
    }

    private fun section(text: String) {
        content.addView(TextView(this).apply {
            this.text = text
            textSize = 15f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setTextColor(0xff23d5ab.toInt())
            setPadding(0, dp(18), 0, dp(5))
        })
    }

    private fun field(title: String, initial: String = "", secret: Boolean = false, multiline: Boolean = false): EditText {
        label(title)
        return EditText(this).apply {
            setText(initial)
            textSize = 15f
            setTextColor(0xffffffff.toInt())
            setHintTextColor(0xff718096.toInt())
            hint = title
            setSingleLine(!multiline && !secret)
            if (secret) inputType = 129
            if (multiline) {
                minLines = 3
                gravity = android.view.Gravity.TOP
            }
            backgroundTintList = android.content.res.ColorStateList.valueOf(0xff65748b.toInt())
            content.addView(this)
        }
    }

    private fun spinner(title: String, values: List<String>): Spinner {
        label(title)
        return Spinner(this).also { s ->
            s.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, values)
            content.addView(s)
        }
    }

    private fun actionButton(title: String, primary: Boolean = false, action: () -> Unit) {
        content.addView(Button(this).apply {
            text = title
            isAllCaps = false
            textSize = 14f
            setTextColor(if (primary) 0xff07151a.toInt() else 0xffffffff.toInt())
            setBackgroundTintList(android.content.res.ColorStateList.valueOf(if (primary) 0xff23d5ab.toInt() else 0xff2a3850.toInt()))
            layoutParams = LinearLayout.LayoutParams(-1, dp(48)).apply { topMargin = dp(9) }
            setOnClickListener { action() }
        })
    }

    private fun buildHome() {
        status = TextView(this).apply {
            textSize = 14f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setTextColor(0xff23d5ab.toInt())
            setPadding(0, dp(8), 0, dp(12))
        }
        content.addView(status)
        section("CONNECTION PROFILE")
        name = field("PROFILE NAME", "My server")
        mode = spinner("CONNECTION MODE", listOf("SSH", "SSH + HTTP Proxy", "SSH + SOCKS5"))
        section("SSH SERVER")
        host = field("SSH HOST")
        port = field("SSH PORT", "22")
        user = field("SSH USERNAME")
        pass = field("SSH PASSWORD", "", true)
        key = field("SSH PRIVATE KEY (optional)", "", true, true)
        knownHosts = field("VERIFIED SSH KNOWN_HOSTS LINE", "", false, true)
        section("UPSTREAM PROXY (OPTIONAL)")
        proxyType = spinner("PROXY TYPE", listOf("HTTP", "SOCKS5"))
        proxyHost = field("PROXY HOST")
        proxyPort = field("PROXY PORT", "8080")
        tls = CheckBox(this).apply {
            text = "Use TLS to connect to proxy"
            setTextColor(0xffffffff.toInt())
            content.addView(this)
        }
        sni = field("TLS SNI / SERVER NAME")
        section("SESSION")
        actionButton("CONNECT", true) {
            try {
                val p = profile()
                validate(p)
                store.save(p)
                AppLog.write(this, "Connect requested for ${p.name}")
                // Start the SSH-backed local SOCKS5 service directly. VPN consent
                // is intentionally deferred until a real TUN forwarding engine is bundled.
                startTunnel()
                refreshStatus()
            } catch (e: Exception) {
                AppLog.write(this, "Configuration error: ${e.message}")
                toast(e.message ?: "Invalid profile")
            }
        }
        actionButton("DISCONNECT") {
            stopService(Intent(this, TunnelService::class.java))
            AppLog.write(this, "Disconnect requested")
            refreshStatus()
        }
        actionButton("SAVE PROFILE") {
            store.save(profile())
            AppLog.write(this, "Profile saved")
            toast("Profile saved on this device")
        }
        actionButton("EXPORT PROFILE") {
            store.save(profile())
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json")
                .putExtra(Intent.EXTRA_TITLE, "juan-vpn-profile.json"), pickExport)
        }
        actionButton("IMPORT PROFILE") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/json")
                .addCategory(Intent.CATEGORY_OPENABLE), pickImport)
        }
        content.addView(TextView(this).apply {
            text = "Security: SSH host-key verification is required. Only connect to servers and proxies you own or are authorized to use."
            textSize = 11f
            setTextColor(0xff9eacc2.toInt())
            setPadding(0, dp(18), 0, dp(8))
        })
        load(store.load())
        refreshStatus()
    }

    private fun buildLogs() {
        section("CONNECTION LOG")
        logView = TextView(this).apply {
            textSize = 12f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextColor(0xffd8e2f0.toInt())
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setBackgroundColor(0xff151f30.toInt())
        }
        content.addView(logView)
        actionButton("REFRESH LOGS", true) { refreshLogs() }
        actionButton("CLEAR LOGS") {
            AppLog.clear(this)
            refreshLogs()
        }
        refreshLogs()
    }

    private fun buildTools() {
        section("NETWORK TOOLS")
        content.addView(TextView(this).apply {
            text = "Connection diagnostics and profile utilities."
            setTextColor(0xffc3cede.toInt())
            textSize = 13f
        })
        actionButton("CHECK SSH CONFIGURATION", true) {
            try {
                validate(profile())
                AppLog.write(this, "Profile validation passed. Network handshake has not been tested.")
                toast("Configuration looks valid")
            } catch (e: Exception) {
                AppLog.write(this, "Validation failed: ${e.message}")
                toast(e.message ?: "Invalid configuration")
            }
        }
        actionButton("OPEN CONNECTION LOG") { showTab("LOGS") }
        actionButton("OPEN HOME") { showTab("HOME") }
        section("CURRENT BUILD")
        content.addView(TextView(this).apply {
            text = "JUAN VPN 1.1.0\nSSH transport foundation · encrypted profile storage · profile import/export · session logging"
            setTextColor(0xff9eacc2.toInt())
            textSize = 12f
        })
    }

    private fun buildHelp() {
        section("HELP & CONNECTION SETUP")
        val help = """
            1. Enter the SSH server hostname and port supplied by your server administrator.
            2. Enter the SSH username and password, or provide a private key.
            3. Add the server's verified OpenSSH known_hosts line. Obtain its fingerprint from your provider through a trusted channel.
            4. Configure an upstream proxy only if your SSH service requires one.
            5. Tap CONNECT and approve Android's VPN consent prompt.

            IMPORTANT
            This project currently starts an SSH-backed local SOCKS5 endpoint. Full-device TUN-to-SOCKS packet forwarding and HTTP CONNECT/TLS proxy chaining are not yet integrated. Do not treat the VPN consent prompt or CONNECTING label as proof that all phone traffic is tunneled.
        """.trimIndent()
        content.addView(TextView(this).apply {
            text = help
            textSize = 13f
            setTextColor(0xffd5deeb.toInt())
            setLineSpacing(dp(4).toFloat(), 1f)
        })
        actionButton("VIEW LOGS", true) { showTab("LOGS") }
    }

    private fun validate(p: Profile) {
        require(p.sshHost.isNotBlank()) { "SSH host is required" }
        require(p.sshPort in 1..65535) { "SSH port must be between 1 and 65535" }
        require(p.username.isNotBlank()) { "SSH username is required" }
        require(p.password.isNotBlank() || p.privateKey.isNotBlank()) { "Enter an SSH password or private key" }
        require(p.knownHosts.isNotBlank()) { "A verified SSH known_hosts line is required" }
        require(p.proxyPort in 1..65535) { "Proxy port must be between 1 and 65535" }
        if (p.tlsEnabled) require(p.sni.isNotBlank()) { "TLS SNI is required when TLS is enabled" }
    }

    private fun profile() = Profile(
        name.text.toString().ifBlank { "My server" },
        mode.selectedItem.toString(),
        host.text.toString().trim(),
        port.text.toString().toIntOrNull() ?: 22,
        user.text.toString().trim(),
        pass.text.toString(),
        key.text.toString(),
        knownHosts.text.toString(),
        proxyHost.text.toString().trim(),
        proxyPort.text.toString().toIntOrNull() ?: 8080,
        proxyType.selectedItem.toString(),
        tls.isChecked,
        sni.text.toString().trim()
    )

    private fun load(p: Profile) {
        name.setText(p.name)
        host.setText(p.sshHost)
        port.setText(p.sshPort.toString())
        user.setText(p.username)
        pass.setText(p.password)
        key.setText(p.privateKey)
        knownHosts.setText(p.knownHosts)
        proxyHost.setText(p.proxyHost)
        proxyPort.setText(p.proxyPort.toString())
        sni.setText(p.sni)
        mode.setSelection((0 until mode.count).firstOrNull { mode.getItemAtPosition(it) == p.mode } ?: 0)
        proxyType.setSelection((0 until proxyType.count).firstOrNull { proxyType.getItemAtPosition(it) == p.proxyType } ?: 0)
        tls.isChecked = p.tlsEnabled
    }

    private fun startTunnel() {
        store.save(profile())
        ContextCompat.startForegroundService(this, Intent(this, TunnelService::class.java))
        status.text = "●  CONNECTING"
    }

    private fun refreshStatus() {
        if (::status.isInitialized) {
            val state = getSharedPreferences("juan_session", MODE_PRIVATE).getString("state", "DISCONNECTED")
            status.text = "●  ${state ?: "DISCONNECTED"}"
        }
    }

    private fun refreshLogs() {
        if (::logView.isInitialized) logView.text = AppLog.read(this)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequest) {
            if (resultCode == Activity.RESULT_OK) startTunnel()
            else {
                AppLog.write(this, "VPN permission was denied")
                toast("VPN permission is required to start the service")
            }
        }
        if (resultCode == Activity.RESULT_OK && data?.data != null) try {
            val uri = data.data!!
            if (requestCode == pickExport) {
                contentResolver.openOutputStream(uri)!!.use { it.write(profile().toJson().toString(2).toByteArray()) }
                AppLog.write(this, "Profile exported")
            }
            if (requestCode == pickImport) {
                val json = contentResolver.openInputStream(uri)!!.bufferedReader().use { it.readText() }
                load(Profile.fromJson(JSONObject(json)))
                store.save(profile())
                AppLog.write(this, "Profile imported")
            }
            toast("Profile operation completed")
        } catch (e: Exception) {
            AppLog.write(this, "Profile file error: ${e.message}")
            toast("Profile error: ${e.message}")
        }
        refreshStatus()
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
}
