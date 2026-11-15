package com.juanvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat

/** Owns the user-visible VPN session lifecycle. The current build starts a local SSH/SOCKS endpoint;
 * full-device TUN-to-SOCKS packet forwarding is intentionally not advertised as implemented. */
class TunnelService : VpnService() {
    private var server: SshSocksServer? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createChannel(); startForeground(41, notification("Starting secure SSH proxy…"))
        Thread {
            try {
                val p = ProfileStore(this).load()
                server = SshSocksServer(p).also { it.start() }
                getSystemService(NotificationManager::class.java).notify(41, notification("SSH connected · SOCKS5 127.0.0.1:${p.socksPort}"))
            } catch (e: Exception) {
                getSystemService(NotificationManager::class.java).notify(41, notification("Connection failed: ${e.message ?: "Unknown error"}"))
                stopSelf()
            }
        }.start()
        return START_NOT_STICKY
    }
    override fun onDestroy() { server?.stop(); server = null; super.onDestroy() }
    private fun createChannel() { if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel("juan_vpn", "JUAN VPN", NotificationManager.IMPORTANCE_LOW)) }
    private fun notification(message: String): Notification = NotificationCompat.Builder(this, "juan_vpn").setSmallIcon(android.R.drawable.stat_sys_upload_done).setContentTitle("JUAN VPN").setContentText(message).setOngoing(true).build()
}
