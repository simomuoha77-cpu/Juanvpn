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
