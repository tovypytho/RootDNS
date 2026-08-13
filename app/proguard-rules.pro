# Tommy RootDNS hardening / R8 rules.
# Entry points referenced by AndroidManifest are kept automatically by AGP/R8.

-allowaccessmodification
-repackageclasses t
-adaptclassstrings
-renamesourcefileattribute T

# Keep only runtime annotation metadata that Android may need.
-keepattributes *Annotation*

# Strip normal Logcat calls in optimized builds.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# Launched by name through root app_process; keep this one entry point stable.
-keep class com.tommy.rootdns.RootPort53Forwarder {
    public static void main(java.lang.String[]);
}
