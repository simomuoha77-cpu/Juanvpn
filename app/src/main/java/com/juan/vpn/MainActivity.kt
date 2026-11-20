package com.juan.vpn

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.*
import org.json.JSONObject

class MainActivity : Activity() {
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText
    private lateinit var proxyHost: EditText
    private lateinit var proxyPort: EditText
    private lateinit var tls: CheckBox
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 32, 28, 24)
            gravity = Gravity.CENTER_HORIZONTAL
            setBackgroundColor(0xFF101827.toInt())
        }
        fun field(label: String, hint: String, secret: Boolean = false): EditText {
            root.addView(TextView(this).apply {
                text = label; setTextColor(0xFFFFFFFF.toInt()); textSize = 14f
            })
            return EditText(this).apply {
                this.hint = hint
                setSingleLine(true)
                setTextColor(0xFFFFFFFF.toInt())
                setHintTextColor(0xFF9CA3AF.toInt())
                if (secret) inputType = 129
                root.addView(this)
            }
        }
        root.addView(TextView(this).apply {
            text = "JUAN VPN"; textSize = 30f; gravity = Gravity.CENTER
            setTextColor(0xFFFFFFFF.toInt())
        })
        root.addView(TextView(this).apply {
            text = "SSH • HTTP Proxy • SOCKS5 • TLS"
            setTextColor(0xFFCBD5E1.toInt()); gravity = Gravity.CENTER
        })
        host = field("SSH server", "vpn.example.com")
        port = field("SSH port", "22")
        username = field("SSH username", "username")
        password = field("SSH password", "Password", true)
        proxyHost = field("HTTP proxy (optional)", "proxy.example.com")
        proxyPort = field("HTTP proxy port", "8080")
        tls = CheckBox(this).apply {
            text = "SSH inside TLS (requires a TLS-wrapped SSH endpoint)"
            setTextColor(0xFFFFFFFF.toInt())
            root.addView(this)
        }
        val export = Button(this).apply { text = "Export configuration" }
        val import = Button(this).apply { text = "Import configuration" }
        val connect = Button(this).apply { text = "Test SSH connection" }
        status = TextView(this).apply {
            text = "Not connected"; setTextColor(0xFFFFFFFF.toInt())
        }
        root.addView(export); root.addView(import); root.addView(connect); root.addView(status)
        setContentView(ScrollView(this).apply { addView(root) })

        export.setOnClickListener { exportConfig() }
        import.setOnClickListener { importConfig() }
        connect.setOnClickListener {
            status.text = "This starter includes configuration UI only. Add the audited SSH/TLS + TUN forwarding engine before routing traffic."
            Toast.makeText(this, "No tunnel is started by this starter build.", Toast.LENGTH_LONG).show()
        }
    }

    private fun config() = JSONObject().apply {
        put("host", host.text.toString())
        put("port", port.text.toString().toIntOrNull() ?: 22)
        put("username", username.text.toString())
        put("password", password.text.toString())
        put("httpProxyHost", proxyHost.text.toString())
        put("httpProxyPort", proxyPort.text.toString().toIntOrNull() ?: 0)
        put("sshOverTls", tls.isChecked)
    }

    private fun exportConfig() {
        val intent = android.content.Intent(android.content.Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(android.content.Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(android.content.Intent.EXTRA_TITLE, "juan-vpn-config.json")
        }
        startActivityForResult(intent, 41)
    }

    private fun importConfig() {
        val intent = android.content.Intent(android.content.Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(android.content.Intent.CATEGORY_OPENABLE)
            type = "application/json"
        }
        startActivityForResult(intent, 42)
    }

    @Deprecated("Use Activity Result APIs in production")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        try {
            if (requestCode == 41) {
                contentResolver.openOutputStream(data.data!!)?.use {
                    it.write(config().toString(2).toByteArray())
                }
                Toast.makeText(this, "Configuration exported", Toast.LENGTH_SHORT).show()
            } else if (requestCode == 42) {
                val json = contentResolver.openInputStream(data.data!!)?.bufferedReader()?.use { it.readText() }
                    ?: return
                val obj = JSONObject(json)
                host.setText(obj.optString("host"))
                port.setText(obj.optInt("port", 22).toString())
                username.setText(obj.optString("username"))
                password.setText(obj.optString("password"))
                proxyHost.setText(obj.optString("httpProxyHost"))
                proxyPort.setText(obj.optInt("httpProxyPort", 0).toString())
                tls.isChecked = obj.optBoolean("sshOverTls", false)
                Toast.makeText(this, "Configuration imported", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "File error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
