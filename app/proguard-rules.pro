# Release hardening: shrink/obfuscate and drop debug-only output (security hardening req. #3)
-repackageclasses ''
-allowaccessmodification
-optimizations !code/simplification/arithmetic

# Strip Log.* and println calls from release so nothing diagnostic survives in the shipped build
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
}
-assumenosideeffects class java.io.PrintStream {
    public void println(%);
    public void println(java.lang.String);
}

# JSON config objects are read by field name via reflection-free org.json, but keep data classes stable
-keepclassmembers class com.juanvpn.app.JuanCfg { *; }
-keep class hev.htproxy.TProxyService { *; }

# JSch loads its ciphers, key exchanges and MACs by class name (Class.forName), so R8 must not rename or drop them.
-keep class com.jcraft.jsch.** { *; }
# Optional integrations JSch and BouncyCastle mention but that are not on Android
-dontwarn com.jcraft.jsch.**
-dontwarn org.ietf.jgss.**
-dontwarn javax.naming.**
-dontwarn javax.security.auth.login.**
-dontwarn com.sun.jna.**
-dontwarn org.slf4j.**
-dontwarn org.apache.logging.log4j.**
-dontwarn org.newsclub.net.unix.**
-dontwarn org.bouncycastle.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
-dontwarn java.lang.management.**
# HJConfig / JSch use the BouncyCastle provider by name
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }
# Smart rotation: keep readable names in failure logs
-keepnames class com.juanvpn.app.JuanFail
