package com.juanvpn.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * This phone's device key for device-bound HJ01 files: an EC P-256 key pair created inside the Android Keystore
 * (hardware-backed where the phone has it, StrongBox first when available). The private half never leaves the
 * Keystore and cannot be exported or backed up, so a copied device-bound file cannot be opened on another phone.
 *
 * Needs Android 12 (API 31): earlier Keystore versions cannot do ECDH. On older phones device binding is simply
 * unavailable and password-protected files keep working.
 *
 * Migration to a new phone = the owner exports again for the new phone's public key. Revocation of this phone's
 * key = [revoke], after which every file bound only to it is permanently unreadable here.
 */
@android.annotation.SuppressLint("NewApi") // every API 31 call is behind `supported`
object HJDeviceKey {
    private const val ALIAS = "juan_hj_device_v1"

    val supported: Boolean get() = Build.VERSION.SDK_INT >= 31

    private fun ks() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** X.509 public key of this phone; creates the key on first use. Null if device binding is unsupported. */
    @Synchronized fun publicKey(): ByteArray? {
        if (!supported) return null
        return try {
            if (!ks().containsAlias(ALIAS)) generate()
            ks().getCertificate(ALIAS).publicKey.encoded
        } catch (_: Throwable) { null }
    }

    @Synchronized fun fingerprint(): String? =
        publicKey()?.let { HJ01.recipientId(it).joinToString("") { b -> "%02x".format(b) } }

    @Synchronized fun revoke() { try { ks().deleteEntry(ALIAS) } catch (_: Throwable) {} }

    private fun generate() {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            if (strongBox && Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(true)
            return b.build()
        }
        val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        try { g.initialize(spec(true)); g.generateKeyPair() }
        catch (_: Throwable) { g.initialize(spec(false)); g.generateKeyPair() }
    }

    /** The key used to open device-bound files, or null when this phone has no device key yet / is unsupported. */
    @Synchronized fun get(): HJ01.DeviceKey? {
        if (!supported) return null
        val pub = try { if (ks().containsAlias(ALIAS)) ks().getCertificate(ALIAS).publicKey.encoded else null } catch (_: Throwable) { null }
            ?: return null
        val id = HJ01.recipientId(pub)
        return object : HJ01.DeviceKey {
            override fun id(): ByteArray = id
            override fun agree(peerPublicX509: ByteArray): ByteArray {
                val priv = ks().getKey(ALIAS, null) as? PrivateKey ?: throw GeneralSecurityException("No device key")
                val peer = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(peerPublicX509))
                val ka = KeyAgreement.getInstance("ECDH")
                ka.init(priv); ka.doPhase(peer, true)
                return ka.generateSecret()
            }
        }
    }
}
