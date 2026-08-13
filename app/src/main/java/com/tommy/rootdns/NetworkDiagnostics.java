package com.tommy.rootdns;

import android.content.Context;
import android.os.Build;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

final class NetworkDiagnostics {
    private NetworkDiagnostics() {}

    static String run(Context context) {
        StringBuilder out = new StringBuilder();
        out.append("TommyRootDNS diagnostics\n");
        out.append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append('\n');
        out.append("app=").append(BuildConfig.VERSION_NAME).append(" (").append(BuildConfig.VERSION_CODE).append(")\n");
        out.append("android=").append(Build.VERSION.RELEASE).append(" api=").append(Build.VERSION.SDK_INT).append('\n');
        out.append("device=").append(safe(Build.MANUFACTURER)).append(' ')
                .append(safe(Build.MODEL)).append('\n');
        out.append("abi=").append(abis()).append('\n');
        out.append("proxy=127.0.0.1:").append(BuildConfig.DNS_PROXY_PORT).append('\n');
        out.append("endpoint=").append(AppPrefs.endpoint(context)).append("\n\n");

        appendCommand(out, "id", RootShell.run("id", 7000));
        appendCommand(out, "uname", RootShell.run("uname -a 2>/dev/null || true", 7000));
        appendCommand(out, "SELinux", RootShell.run("getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null || true", 7000));
        appendCommand(out, "capabilities", RootShell.run("grep -E '^Cap(Inh|Prm|Eff|Bnd):' /proc/self/status 2>/dev/null || true", 7000));
        appendCommand(out, "PATH", RootShell.run("printf '%s' \"$PATH\"", 7000));
        appendCommand(out, "netfilter tables", RootShell.run("cat /proc/net/ip_tables_names 2>/dev/null || true", 7000));
        appendCommand(out, "ip6 tables", RootShell.run("cat /proc/net/ip6_tables_names 2>/dev/null || true", 7000));

        out.append('\n').append(IptablesManager.probe(BuildConfig.DNS_PROXY_PORT)).append('\n');
        return limit(out.toString(), 24000);
    }

    private static void appendCommand(StringBuilder out, String name, RootShell.Result result) {
        out.append("=== ").append(name).append(" ===\n");
        out.append("code=").append(result.code).append('\n');
        String value = result.output == null ? "" : result.output.trim();
        out.append(value.length() == 0 ? "(no output)" : value).append("\n\n");
    }

    private static String abis() {
        if (Build.VERSION.SDK_INT >= 21 && Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0) {
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < Build.SUPPORTED_ABIS.length; i++) {
                if (i > 0) b.append(',');
                b.append(Build.SUPPORTED_ABIS[i]);
            }
            return b.toString();
        }
        return safe(Build.CPU_ABI);
    }

    private static String limit(String value, int max) {
        if (value.length() <= max) return value;
        return value.substring(0, max) + "\n[diagnostics truncated]";
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value;
    }
}
