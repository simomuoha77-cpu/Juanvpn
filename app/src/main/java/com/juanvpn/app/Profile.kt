package com.juanvpn.app

import org.json.JSONObject

data class Profile(
    val name: String = "My server",
    val mode: String = "SSH",
    val sshHost: String = "",
    val sshPort: Int = 22,
    val username: String = "",
    val password: String = "",
    val privateKey: String = "",
    val knownHosts: String = "",
    val proxyHost: String = "",
    val proxyPort: Int = 8080,
    val proxyType: String = "HTTP",
    val tlsEnabled: Boolean = false,
    val sni: String = "",
    val socksHost: String = "127.0.0.1",
    val socksPort: Int = 1080
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("format", "juanvpn-profile-v1"); put("name", name); put("mode", mode)
        put("sshHost", sshHost); put("sshPort", sshPort); put("username", username)
        put("password", password); put("privateKey", privateKey); put("knownHosts", knownHosts); put("proxyHost", proxyHost)
        put("proxyPort", proxyPort); put("proxyType", proxyType); put("tlsEnabled", tlsEnabled)
        put("sni", sni); put("socksHost", socksHost); put("socksPort", socksPort)
    }
    companion object {
        fun fromJson(j: JSONObject): Profile {
            require(j.optString("format") == "juanvpn-profile-v1") { "Unsupported profile format" }
            return Profile(j.optString("name", "Imported"), j.optString("mode", "SSH"),
                j.optString("sshHost"), j.optInt("sshPort", 22), j.optString("username"),
                j.optString("password"), j.optString("privateKey"), j.optString("knownHosts"), j.optString("proxyHost"),
                j.optInt("proxyPort", 8080), j.optString("proxyType", "HTTP"),
                j.optBoolean("tlsEnabled"), j.optString("sni"), j.optString("socksHost", "127.0.0.1"), j.optInt("socksPort", 1080))
        }
    }
}
