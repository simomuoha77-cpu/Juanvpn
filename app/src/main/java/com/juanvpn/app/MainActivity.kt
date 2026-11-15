package com.juanvpn.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var store: ProfileStore
    private lateinit var name: EditText; private lateinit var host: EditText; private lateinit var port: EditText
    private lateinit var user: EditText; private lateinit var pass: EditText; private lateinit var key: EditText
    private lateinit var knownHosts: EditText; private lateinit var proxyHost: EditText; private lateinit var proxyPort: EditText; private lateinit var sni: EditText
    private lateinit var mode: Spinner; private lateinit var proxyType: Spinner; private lateinit var tls: CheckBox; private lateinit var status: TextView
    private val pickExport = 701; private val pickImport = 702
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); store = ProfileStore(this); buildUi(); load(store.load()); if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 703) }
    private fun field(parent: LinearLayout, label: String, value: String = "", secret: Boolean = false): EditText {
        parent.addView(TextView(this).apply { text = label; textSize = 13f; setTextColor(0xffaebbd0.toInt()) })
        return EditText(this).apply { setText(value); setSingleLine(!secret); if (secret) inputType = 129; setTextColor(0xffffffff.toInt()); setHintTextColor(0xff8492a8.toInt()); hint = label; parent.addView(this) }
    }
    private fun buildUi() {
        val root = LinearLayout(this).apply { orientation = 1; setPadding(24, 24, 24, 24); setBackgroundColor(0xff101522.toInt()) }
        val scroll = ScrollView(this); scroll.addView(root); setContentView(scroll)
        root.addView(TextView(this).apply { text = "JUAN VPN"; textSize = 30f; setTextColor(-1); typeface = android.graphics.Typeface.DEFAULT_BOLD })
        root.addView(TextView(this).apply { text = "SECURE CONNECTION CLIENT  ·  v1.0.0"; textSize = 11f; setTextColor(0xff23d5ab.toInt()) })
        status = TextView(this).apply { text = "●  DISCONNECTED"; textSize = 14f; setTextColor(0xff23d5ab.toInt()); setPadding(0, 22, 0, 18) }; root.addView(status)
        name = field(root, "PROFILE NAME"); mode = spinner(root, "CONNECTION MODE", listOf("SSH", "HTTP Proxy", "SOCKS5"))
        host = field(root, "SSH HOST"); port = field(root, "SSH PORT", "22"); user = field(root, "SSH USERNAME"); pass = field(root, "SSH PASSWORD", "", true); key = field(root, "SSH PRIVATE KEY (optional)"); knownHosts = field(root, "VERIFIED SSH KNOWN_HOSTS LINE")
        proxyType = spinner(root, "PROXY TYPE", listOf("HTTP", "SOCKS5")); proxyHost = field(root, "PROXY HOST"); proxyPort = field(root, "PROXY PORT", "8080"); tls = CheckBox(this).apply { text = "Enable TLS for proxy transport"; setTextColor(-1); root.addView(this) }; sni = field(root, "TLS SNI / SERVER NAME")
        val connect = button("CONNECT", 0xff23d5ab.toInt()) { save(); val prepare = VpnService.prepare(this); if (prepare != null) startActivityForResult(prepare, 700) else startTunnel() }; root.addView(connect)
        root.addView(button("DISCONNECT", 0xff35415a.toInt()) { stopService(Intent(this, TunnelService::class.java)); status.text = "●  DISCONNECTED" })
        root.addView(button("SAVE PROFILE", 0xff35415a.toInt()) { save(); toast("Profile saved securely") })
        root.addView(button("EXPORT PROFILE", 0xff35415a.toInt()) { save(); startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").putExtra(Intent.EXTRA_TITLE, "juan-vpn-profile.json"), pickExport) })
        root.addView(button("IMPORT PROFILE", 0xff35415a.toInt()) { startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE), pickImport) })
        root.addView(TextView(this).apply { text = "Your SSH credentials are stored with Android encrypted preferences. Only connect to servers you own or are authorized to use. This build provides an SSH-backed local SOCKS5 endpoint; full-device VPN packet routing is not yet included."; textSize = 12f; setTextColor(0xffaebbd0.toInt()); setPadding(0, 22, 0, 16) })
    }
    private fun spinner(root: LinearLayout, label: String, values: List<String>) = Spinner(this).also { s -> root.addView(TextView(this).apply { text = label; setTextColor(0xffaebbd0.toInt()) }); s.adapter = android.widget.ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, values); root.addView(s) }
    private fun button(label: String, color: Int, action: () -> Unit) = Button(this).apply { text = label; setTextColor(0xff101522.toInt()); setBackgroundTintList(android.content.res.ColorStateList.valueOf(color)); setOnClickListener { action() } }
    private fun profile() = Profile(name.text.toString().ifBlank { "My server" }, mode.selectedItem.toString(), host.text.toString().trim(), port.text.toString().toIntOrNull() ?: 22, user.text.toString().trim(), pass.text.toString(), key.text.toString(), knownHosts.text.toString(), proxyHost.text.toString().trim(), proxyPort.text.toString().toIntOrNull() ?: 8080, proxyType.selectedItem.toString(), tls.isChecked, sni.text.toString().trim())
    private fun save() { store.save(profile()) }
    private fun load(p: Profile) { name.setText(p.name); host.setText(p.sshHost); port.setText(p.sshPort.toString()); user.setText(p.username); pass.setText(p.password); key.setText(p.privateKey); knownHosts.setText(p.knownHosts); proxyHost.setText(p.proxyHost); proxyPort.setText(p.proxyPort.toString()); sni.setText(p.sni); mode.setSelection((mode.adapter as android.widget.ArrayAdapter<String>).getPosition(p.mode)); proxyType.setSelection((proxyType.adapter as android.widget.ArrayAdapter<String>).getPosition(p.proxyType)); tls.isChecked = p.tlsEnabled }
    private fun startTunnel() { save(); ContextCompat.startForegroundService(this, Intent(this, TunnelService::class.java)); status.text = "●  CONNECTING" }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) { super.onActivityResult(requestCode, resultCode, data); if (requestCode == 700 && resultCode == Activity.RESULT_OK) startTunnel(); if (resultCode == Activity.RESULT_OK && data?.data != null) try { val uri = data.data!!; if (requestCode == pickExport) contentResolver.openOutputStream(uri)!!.use { it.write(profile().toJson().toString(2).toByteArray()) }; if (requestCode == pickImport) { val j = contentResolver.openInputStream(uri)!!.bufferedReader().use { it.readText() }; load(Profile.fromJson(JSONObject(j))); save() }; toast("Profile operation completed") } catch (e: Exception) { toast("Profile error: ${e.message}") } }
    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
}
