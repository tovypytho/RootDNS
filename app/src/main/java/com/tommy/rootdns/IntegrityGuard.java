package com.tommy.rootdns;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.ApplicationInfo;
import android.os.Debug;
import java.security.MessageDigest;
import java.util.Locale;

final class IntegrityGuard {
    private IntegrityGuard() {}

    static boolean isTrusted(Context context) {
        if (!"com.tommy.rootdns".equals(context.getPackageName())) return false;
        if ((context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) return false;
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) return false;
        String expected = BuildConfig.EXPECTED_CERT_SHA256;
        if (expected == null || expected.length() == 0) return true;
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            Signature[] signatures = info.signatures;
            if (signatures == null || signatures.length == 0) return false;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(signatures[0].toByteArray());
            return expected.equals(hex(hash));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format(Locale.US, "%02x", b & 0xFF));
        return out.toString();
    }
}
