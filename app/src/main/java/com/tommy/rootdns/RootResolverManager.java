package com.tommy.rootdns;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collection;

/**
 * Root fallback for Android builds that have neither netfilter nor TUN.
 *
 * A tiny root app_process bridge owns localhost:53 and forwards to the app's
 * normal unprivileged DoH proxy on localhost:5454. netd's per-network resolver
 * is then pointed at 127.0.0.1. No iptables or VpnService is required.
 */
final class RootResolverManager {
    private static final String PID = "/data/local/tmp/tommy_dns53.pid";
    private static final String LOG = "/data/local/tmp/tommy_dns53.log";

    private RootResolverManager() {}

    static RootShell.Result enable(Context context, int proxyPort) {
        StringBuilder out = new StringBuilder();
        out.append("TommyRootDNS root resolver enable\n");
        out.append("proxy=127.0.0.1:").append(proxyPort).append('\n');

        if (!RootShell.hasRoot()) return new RootShell.Result(40, out.append("ERROR: root unavailable").toString());

        ResolverState state = currentState(context);
        if (state.netId <= 0) {
            return new RootShell.Result(41, out.append("ERROR: no active Android network/netId").toString());
        }
        out.append("active netId=").append(state.netId).append('\n');
        out.append("original DNS=").append(state.dns.length() == 0 ? "(none)" : state.dns).append('\n');
        out.append("domains=").append(state.domains.length() == 0 ? "(none)" : state.domains).append('\n');

        String oldProp1 = clean(RootShell.run("getprop net.dns1 2>/dev/null || true", 5000).output);
        String oldProp2 = clean(RootShell.run("getprop net.dns2 2>/dev/null || true", 5000).output);
        AppPrefs.resolverBackup(context, state.netId, state.dns, state.domains, oldProp1, oldProp2);

        RootShell.Result appProcess = RootShell.run(
                "for p in /system/bin/app_process /system/bin/app_process64 /system/bin/app_process32; do " +
                "[ -x \"$p\" ] && { echo \"$p\"; exit 0; }; done; exit 1", 5000);
        if (!appProcess.ok() || clean(appProcess.output).length() == 0) {
            return new RootShell.Result(42, out.append("ERROR: app_process executable not found\n")
                    .append(appProcess.output).toString());
        }
        String appProcessPath = clean(appProcess.output).split("\\s+")[0];
        out.append("app_process=").append(appProcessPath).append('\n');

        stopHelper();
        String apk = context.getApplicationInfo().sourceDir;
        String start = "rm -f " + PID + " " + LOG + "; " +
                "(CLASSPATH=" + quote(apk) + " " + quote(appProcessPath) +
                " /system/bin com.tommy.rootdns.RootPort53Forwarder " + proxyPort +
                " >" + LOG + " 2>&1 & echo $! >" + PID + "); " +
                "sleep 1; echo pid=$(cat " + PID + " 2>/dev/null); cat " + LOG + " 2>/dev/null || true";
        RootShell.Result helper = RootShell.run(start, 8000);
        out.append("helper start: code=").append(helper.code).append(" • ").append(oneLine(helper.output)).append('\n');
        if (!probeLocalDns53()) {
            out.append("ERROR: localhost:53 bridge did not answer DNS\n");
            RootShell.Result details = RootShell.run("cat " + LOG + " 2>/dev/null || true", 4000);
            if (details.output.length() > 0) out.append(details.output).append('\n');
            stopHelper();
            return new RootShell.Result(43, out.toString());
        }
        out.append("localhost:53 DNS bridge=OK\n");

        RootShell.Result ndcProbe = RootShell.run("command -v ndc 2>/dev/null || ls /system/bin/ndc 2>/dev/null || true", 5000);
        out.append("ndc probe: ").append(oneLine(ndcProbe.output)).append('\n');

        RootShell.Result apply = applyResolver(state.netId);
        out.append("resolver setnetdns: code=").append(apply.code).append(" • ").append(oneLine(apply.output)).append('\n');
        if (!resolverCommandLooksSuccessful(apply)) {
            restore(context);
            stopHelper();
            return new RootShell.Result(44, out.append("ERROR: netd resolver override failed").toString());
        }

        RootShell.run("setprop net.dns1 127.0.0.1; setprop net.dns2 127.0.0.1", 5000);
        RootShell.Result flush = RootShell.run("ndc resolver flushnet " + state.netId + " 2>&1 || true", 5000);
        out.append("resolver flush: ").append(oneLine(flush.output)).append('\n');
        out.append("ROOT_RESOLVER_OK\n");
        return new RootShell.Result(0, out.toString());
    }

    static void disable(Context context) {
        restore(context);
        stopHelper();
        AppPrefs.clearResolverBackup(context);
    }

    static boolean ensure(Context context) {
        if (!probeLocalDns53()) return false;
        ResolverState state = currentState(context);
        if (state.netId <= 0) return false;
        int saved = AppPrefs.resolverNetId(context);
        if (saved != state.netId) {
            // The old network is gone. Save this network's real LinkProperties before overriding it.
            String p1 = clean(RootShell.run("getprop net.dns1 2>/dev/null || true", 4000).output);
            String p2 = clean(RootShell.run("getprop net.dns2 2>/dev/null || true", 4000).output);
            AppPrefs.resolverBackup(context, state.netId, state.dns, state.domains, p1, p2);
        }
        RootShell.Result apply = applyResolver(state.netId);
        if (!resolverCommandLooksSuccessful(apply)) return false;
        RootShell.run("setprop net.dns1 127.0.0.1; setprop net.dns2 127.0.0.1", 4000);
        return true;
    }

    static String diagnostics(Context context) {
        StringBuilder out = new StringBuilder();
        out.append("=== ROOT RESOLVER FALLBACK ===\n");
        ResolverState s = currentState(context);
        out.append("active netId: ").append(s.netId <= 0 ? "unavailable" : Integer.toString(s.netId)).append('\n');
        out.append("LinkProperties DNS: ").append(s.dns.length() == 0 ? "(none)" : s.dns).append('\n');
        out.append("LinkProperties domains: ").append(s.domains.length() == 0 ? "(none)" : s.domains).append('\n');
        out.append("saved netId: ").append(AppPrefs.resolverNetId(context)).append('\n');
        out.append("saved DNS: ").append(valueOrNone(AppPrefs.resolverDns(context))).append('\n');
        out.append("net.dns1: ").append(valueOrNone(clean(RootShell.run("getprop net.dns1 2>/dev/null || true", 4000).output))).append('\n');
        out.append("net.dns2: ").append(valueOrNone(clean(RootShell.run("getprop net.dns2 2>/dev/null || true", 4000).output))).append('\n');
        RootShell.Result ndc = RootShell.run("command -v ndc 2>/dev/null || ls /system/bin/ndc 2>/dev/null || true", 4000);
        out.append("ndc: ").append(valueOrNone(clean(ndc.output))).append('\n');
        RootShell.Result ap = RootShell.run("ls -l /system/bin/app_process* 2>/dev/null || true", 4000);
        out.append("app_process: ").append(valueOrNone(oneLine(ap.output))).append('\n');
        RootShell.Result pid = RootShell.run("cat " + PID + " 2>/dev/null || true", 4000);
        out.append("helper pid: ").append(valueOrNone(clean(pid.output))).append('\n');
        RootShell.Result log = RootShell.run("tail -n 8 " + LOG + " 2>/dev/null || true", 4000);
        out.append("helper log: ").append(valueOrNone(oneLine(log.output))).append('\n');
        out.append("localhost:53 probe: ").append(probeLocalDns53() ? "OK" : "FAIL").append('\n');
        out.append("strategy: netd resolver -> 127.0.0.1:53 -> root bridge -> 127.0.0.1:")
                .append(BuildConfig.DNS_PROXY_PORT).append(" -> DoH\n");
        return out.toString();
    }

    private static RootShell.Result applyResolver(int netId) {
        return RootShell.run("ndc resolver setnetdns " + netId + " '' 127.0.0.1 2>&1", 7000);
    }

    private static void restore(Context context) {
        int netId = AppPrefs.resolverNetId(context);
        if (netId <= 0) return;
        String dns = clean(AppPrefs.resolverDns(context));
        String domains = clean(AppPrefs.resolverDomains(context));
        String cmd;
        if (dns.length() > 0) {
            cmd = "ndc resolver setnetdns " + netId + " " + quote(domains) + " " + dns + " 2>&1 || true; " +
                    "ndc resolver flushnet " + netId + " 2>&1 || true";
        } else {
            cmd = "ndc resolver clearnetdns " + netId + " 2>&1 || true; " +
                    "ndc resolver flushnet " + netId + " 2>&1 || true";
        }
        RootShell.run(cmd, 7000);
        RootShell.run("setprop net.dns1 " + quote(AppPrefs.resolverProp1(context)) + "; " +
                "setprop net.dns2 " + quote(AppPrefs.resolverProp2(context)), 5000);
    }

    private static void stopHelper() {
        RootShell.run("if [ -f " + PID + " ]; then p=$(cat " + PID + " 2>/dev/null); " +
                "[ -n \"$p\" ] && kill \"$p\" 2>/dev/null || true; fi; rm -f " + PID, 5000);
    }

    private static boolean probeLocalDns53() {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
            byte[] query = DnsPackets.aQuery("example.com");
            DatagramPacket p = new DatagramPacket(query, query.length,
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 53));
            socket.send(p);
            byte[] buf = new byte[4096];
            DatagramPacket r = new DatagramPacket(buf, buf.length);
            socket.receive(r);
            return r.getLength() >= 12 && (buf[2] & 0x80) != 0;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (socket != null) socket.close();
        }
    }

    private static ResolverState currentState(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return new ResolverState(-1, "", "");
            Network network = cm.getActiveNetwork();
            if (network == null) return new ResolverState(-1, "", "");
            int netId;
            try { netId = Integer.parseInt(network.toString().trim()); }
            catch (NumberFormatException e) { return new ResolverState(-1, "", ""); }
            LinkProperties lp = cm.getLinkProperties(network);
            StringBuilder dns = new StringBuilder();
            String domains = "";
            if (lp != null) {
                Collection<InetAddress> servers = lp.getDnsServers();
                if (servers != null) {
                    for (InetAddress a : servers) {
                        if (a == null) continue;
                        String host = a.getHostAddress();
                        if (host == null || host.length() == 0 || host.indexOf(':') >= 0) continue;
                        if (dns.length() > 0) dns.append(' ');
                        dns.append(host);
                    }
                }
                if (lp.getDomains() != null) domains = lp.getDomains();
            }
            return new ResolverState(netId, dns.toString(), domains);
        } catch (Throwable ignored) {
            return new ResolverState(-1, "", "");
        }
    }

    private static boolean resolverCommandLooksSuccessful(RootShell.Result result) {
        if (result == null || result.code != 0) return false;
        String lower = result.output == null ? "" : result.output.toLowerCase();
        return lower.indexOf("failed") < 0 && lower.indexOf("error") < 0 && lower.indexOf("unknown command") < 0;
    }

    private static String quote(String value) {
        if (value == null) value = "";
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String oneLine(String value) {
        value = clean(value);
        return value.length() == 0 ? "(no output)" : value.replace('\n', ' ').replace('\r', ' ');
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private static String valueOrNone(String value) {
        return value == null || value.length() == 0 ? "(none)" : value;
    }

    private static final class ResolverState {
        final int netId;
        final String dns;
        final String domains;
        ResolverState(int netId, String dns, String domains) {
            this.netId = netId;
            this.dns = dns == null ? "" : dns;
            this.domains = domains == null ? "" : domains;
        }
    }
}
