package com.juanvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * Session owner. This release currently exposes the SSH-backed local SOCKS5
 * endpoint only. It deliberately does not establish a TUN interface until the
 * native tun2socks bridge is bundled and configured.
 */
class TunnelService : VpnService() {
    @Volatile private var server: SshSocksServer? = null
    @Volatile private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createChannel()
        startForeground(41, notification("Connecting to SSH server…"))
        AppLog.setState(this, "CONNECTING")
        AppLog.write(this, "Starting SSH authentication")
        worker?.interrupt()
        worker = Thread {
            try {
                val profile = ProfileStore(this).load()
                val ssh = SshSocksServer(profile)
                ssh.start()
                server = ssh
                AppLog.setState(this, "SSH READY · LOCAL SOCKS5")
                AppLog.write(this, "SSH authenticated; local SOCKS5 listening on 127.0.0.1:${profile.socksPort}")
                getSystemService(NotificationManager::class.java).notify(
                    41, notification("SSH ready · SOCKS5 127.0.0.1:${profile.socksPort}")
                )
            } catch (e: Exception) {
                AppLog.setState(this, "FAILED")
                AppLog.write(this, "Connection failed: ${e.message ?: e.javaClass.simpleName}")
                getSystemService(NotificationManager::class.java).notify(
                    41, notification("Connection failed: ${e.message ?: "Check Logs"}")
                )
                stopSelf()
            }
        }.apply { name = "JuanVpnSshConnect"; start() }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        AppLog.write(this, "Tunnel service stopped")
        server?.stop()
        server = null
        worker?.interrupt()
        worker = null
        AppLog.setState(this, "DISCONNECTED")
        super.onDestroy()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel("juan_vpn", "JUAN VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notification(message: String): Notification =
        NotificationCompat.Builder(this, "juan_vpn")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("JUAN VPN")
            .setContentText(message)
            .setOngoing(true)
            .build()
}
