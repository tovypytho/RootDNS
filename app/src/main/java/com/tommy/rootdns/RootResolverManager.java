package com.tommy.rootdns;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Root resolver fallback for virtual Android builds without usable netfilter/TUN.
 *
 * v1.8 supports Android 5-7 per-network netd/property resolver stacks and uses a
 * native root DNS53 helper. UDP clients on port 53 are translated to the app proxy's
 * proven TCP DNS listener, avoiding vendor-specific loss on the Java UDP backend.
 */
final class RootResolverManager {
    private static final String PID = "/data/local/tmp/tommy_dns53.pid";
    private static final String LOG = "/data/local/tmp/tommy_dns53.log";
    private static final String BIN = "/data/local/tmp/tommy_dns53";
    private static final Pattern ACTIVE_DEFAULT = Pattern.compile("(?m)^\\s*Active default network:\\s*(\\d+)\\s*$");
    private static final Pattern NETWORK_WRAPPED = Pattern.compile("network\\{(\\d+)\\}");

    private RootResolverManager() {}

    static RootShell.Result enable(Context context, int proxyPort) {
        StringBuilder out = new StringBuilder();
        out.append("TommyRootDNS root resolver enable\n");
        out.append("proxy=127.0.0.1:").append(proxyPort).append('\n');

        if (!RootShell.hasRoot()) {
            return new RootShell.Result(40, out.append("ERROR: root unavailable").toString());
        }

        ResolverState state = currentState(context);
        out.append("network source=").append(valueOrNone(state.source)).append('\n');
        out.append("active netId=").append(state.netId > 0 ? state.netId : "unavailable").append('\n');
        out.append("default iface=").append(valueOrNone(state.iface)).append('\n');
        out.append("original DNS=").append(valueOrNone(state.dns)).append('\n');
        out.append("domains=").append(valueOrNone(state.domains)).append('\n');

        String oldProp1 = prop("net.dns1");
        String oldProp2 = prop("net.dns2");
        String oldDnsChange = prop("net.dnschange");
        AppPrefs.resolverBackup(context, state.netId, state.dns, state.domains,
                oldProp1, oldProp2, state.iface, oldDnsChange, "");

        // Prove the ordinary app-side proxy is answering before inserting the privileged
        // port-53 bridge. This isolates DoH/proxy failures from root-helper failures.
        boolean backendUdp = probeDnsUdp(proxyPort, 1500);
        boolean backendTcp = probeDnsTcp(proxyPort, 15000);
        out.append("backend 127.0.0.1:").append(proxyPort)
                .append(" UDP=").append(backendUdp ? "OK" : "FAIL")
                .append(" TCP=").append(backendTcp ? "OK" : "FAIL").append('\n');
        out.append("bridge backend transport=TCP (UDP/53 clients are translated to TCP/5454)\n");
        if (!backendTcp) {
            return new RootShell.Result(41, out.append("ERROR: app DNS proxy TCP listener did not answer before root bridge").toString());
        }

        // Start localhost:53 before requiring a netId. v1.8 uses a tiny NDK-built native
        // helper instead of app_process; some virtual Android builds allow a root native
        // executable from /data/local/tmp but silently kill/deny app_process loading APK dex.
        RootShell.Result helper = startHelper(context, proxyPort);
        out.append("helper start: code=").append(helper.code).append(" • ")
                .append(oneLine(helper.output)).append('\n');
        boolean localUdp = probeDnsUdp(53, 15000);
        boolean localTcp = probeDnsTcp(53, 15000);
        out.append("localhost:53 UDP=").append(localUdp ? "OK" : "FAIL")
                .append(" TCP=").append(localTcp ? "OK" : "FAIL").append('\n');
        if (!localUdp) {
            out.append("ERROR: localhost:53 bridge did not answer DNS\n");
            RootShell.Result details = RootShell.run("cat " + LOG + " 2>/dev/null || true", 4000);
            if (details.output.length() > 0) out.append(details.output).append('\n');
            stopHelper();
            return new RootShell.Result(43, out.toString());
        }
        out.append("localhost:53 DNS bridge=OK\n");

        ApplyResult applied = applyBestResolver(state);
        out.append(applied.log);
        if (!applied.ok) {
            restore(context);
            stopHelper();
            return new RootShell.Result(44, out.append("ERROR: no compatible Android resolver override worked").toString());
        }

        AppPrefs.resolverStrategy(context, applied.method);
        out.append("RESOLVER_METHOD=").append(applied.method).append('\n');
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
        String method = AppPrefs.resolverStrategy(context);

        if ("setnetdns".equals(method) && state.netId > 0) {
            RootShell.Result r = applyNetId(state.netId);
            if (!commandLooksSuccessful(r)) return false;
            applyPropertiesOnly();
            return true;
        }
        if ("legacy-iface".equals(method) && state.iface.length() > 0) {
            RootShell.Result r = applyLegacyIface(state.iface);
            if (!commandLooksSuccessful(r)) return false;
            applyPropertiesOnly();
            return true;
        }

        // Property mode is specifically for vendor/virtual Android stacks where
        // ConnectivityManager/netId are unavailable but net.dns* is authoritative.
        RootShell.Result props = applyPropertiesOnly();
        return props.ok() && "127.0.0.1".equals(prop("net.dns1"));
    }

    static String diagnostics(Context context) {
        StringBuilder out = new StringBuilder();
        out.append("=== ROOT RESOLVER FALLBACK ===\n");
        ResolverState s = currentState(context);
        out.append("network source: ").append(valueOrNone(s.source)).append('\n');
        out.append("active netId: ").append(s.netId <= 0 ? "unavailable" : Integer.toString(s.netId)).append('\n');
        out.append("default iface: ").append(valueOrNone(s.iface)).append('\n');
        out.append("resolver strategy: ").append(valueOrNone(AppPrefs.resolverStrategy(context))).append('\n');
        out.append("LinkProperties/property DNS: ").append(valueOrNone(s.dns)).append('\n');
        out.append("domains: ").append(valueOrNone(s.domains)).append('\n');
        out.append("saved netId: ").append(AppPrefs.resolverNetId(context)).append('\n');
        out.append("saved iface: ").append(valueOrNone(AppPrefs.resolverIface(context))).append('\n');
        out.append("saved DNS: ").append(valueOrNone(AppPrefs.resolverDns(context))).append('\n');
        out.append("net.dns1: ").append(valueOrNone(prop("net.dns1"))).append('\n');
        out.append("net.dns2: ").append(valueOrNone(prop("net.dns2"))).append('\n');
        out.append("net.dnschange: ").append(valueOrNone(prop("net.dnschange"))).append('\n');
        RootShell.Result route = RootShell.run("cat /proc/net/route 2>/dev/null | head -n 12 || true", 4000);
        out.append("route table: ").append(valueOrNone(oneLine(route.output))).append('\n');
        RootShell.Result conn = RootShell.run("dumpsys connectivity 2>/dev/null | grep -E 'Active default network|network\\{|InterfaceName:|DnsAddresses:' | head -n 12 || true", 6000);
        out.append("connectivity summary: ").append(valueOrNone(oneLine(conn.output))).append('\n');
        RootShell.Result ndc = RootShell.run("command -v ndc 2>/dev/null || ls /system/bin/ndc 2>/dev/null || true", 4000);
        out.append("ndc: ").append(valueOrNone(clean(ndc.output))).append('\n');
        RootShell.Result ndcProbe = RootShell.run("ndc resolver 2>&1 || true", 4000);
        out.append("ndc resolver probe: ").append(valueOrNone(oneLine(ndcProbe.output))).append('\n');
        RootShell.Result nativePkg = RootShell.run("ls -lZ " + quote(context.getApplicationInfo().nativeLibraryDir + "/libtdns53.so") + " 2>&1 || true", 4000);
        out.append("packaged native helper: ").append(valueOrNone(oneLine(nativePkg.output))).append('\n');
        RootShell.Result nativeTmp = RootShell.run("ls -lZ " + BIN + " 2>&1 || ls -l " + BIN + " 2>&1 || true", 4000);
        out.append("root helper binary: ").append(valueOrNone(oneLine(nativeTmp.output))).append('\n');
        RootShell.Result ap = RootShell.run("ls -l /system/bin/app_process* 2>/dev/null || true", 4000);
        out.append("app_process fallback: ").append(valueOrNone(oneLine(ap.output))).append('\n');
        RootShell.Result pid = RootShell.run("p=$(cat " + PID + " 2>/dev/null); echo pid=$p; if [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null; then echo alive=yes; else echo alive=no; fi", 4000);
        out.append("helper process: ").append(valueOrNone(oneLine(pid.output))).append('\n');
        RootShell.Result log = RootShell.run("tail -n 20 " + LOG + " 2>/dev/null || true", 4000);
        out.append("helper log: ").append(valueOrNone(oneLine(log.output))).append('\n');
        out.append("backend 127.0.0.1:").append(BuildConfig.DNS_PROXY_PORT)
                .append(" UDP=").append(probeDnsUdp(BuildConfig.DNS_PROXY_PORT, 1500) ? "OK" : "FAIL")
                .append(" TCP=").append(probeDnsTcp(BuildConfig.DNS_PROXY_PORT, 12000) ? "OK" : "FAIL").append('\n');
        out.append("bridge backend transport: TCP\n");
        out.append("localhost:53 UDP=").append(probeDnsUdp(53, 8000) ? "OK" : "FAIL")
                .append(" TCP=").append(probeDnsTcp(53, 8000) ? "OK" : "FAIL").append('\n');
        out.append("strategy order: setnetdns -> legacy interface resolver -> net.dns properties\n");
        out.append("data path: Android resolver -> 127.0.0.1:53 -> root bridge -> 127.0.0.1:")
                .append(BuildConfig.DNS_PROXY_PORT).append(" -> DoH\n");
        return out.toString();
    }

    private static RootShell.Result startHelper(Context context, int proxyPort) {
        stopHelper();

        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        String packaged = nativeDir == null ? "" : nativeDir + "/libtdns53.so";
        if (packaged.length() == 0) {
            return new RootShell.Result(42, "nativeLibraryDir unavailable");
        }
        String staged = stageNativeHelper(context, packaged);

        String qsrc = quote(packaged);
        String qstage = staged.length() == 0 ? "''" : quote(staged);
        String prep =
                "rm -f " + quote(BIN) + " " + quote(PID) + " " + quote(LOG) + "; " +
                "src=" + qsrc + "; if [ ! -r \"$src\" ] && [ -n " + qstage + " ] && [ -r " + qstage + " ]; then src=" + qstage + "; fi; " +
                "if [ ! -r \"$src\" ]; then echo 'native helper source unreadable'; echo packaged=" + qsrc + "; echo staged=" + qstage + "; exit 42; fi; " +
                "cat \"$src\" > " + quote(BIN) + " || exit 43; " +
                "chmod 0755 " + quote(BIN) + " || exit 44; " +
                "(" + quote(BIN) + " " + proxyPort + " >" + quote(LOG) + " 2>&1 </dev/null & echo $! >" + quote(PID) + "); " +
                "ready=0; i=0; while [ $i -lt 8 ]; do i=$((i+1)); " +
                "p=$(cat " + quote(PID) + " 2>/dev/null); " +
                "if [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null && grep -q '^READY ' " + quote(LOG) + " 2>/dev/null; then ready=1; break; fi; " +
                "sleep 1; done; " +
                "p=$(cat " + quote(PID) + " 2>/dev/null); " +
                "echo backend=native; echo source=$src; echo pid=$p; " +
                "if [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null; then echo alive=yes; else echo alive=no; fi; " +
                "cat " + quote(LOG) + " 2>/dev/null || true; " +
                "[ $ready -eq 1 ]";
        RootShell.Result nativeStart = RootShell.run(prep, 14000);
        if (nativeStart.ok()) return nativeStart;

        // Last-resort compatibility fallback for builds that somehow omit/exclude the native
        // helper. app_process is retained only as a diagnostic fallback, not the primary path.
        RootShell.Result appProcess = RootShell.run(
                "for p in /system/bin/app_process /system/bin/app_process64 /system/bin/app_process32; do " +
                "[ -x \"$p\" ] && { echo \"$p\"; exit 0; }; done; exit 1", 5000);
        if (!appProcess.ok() || clean(appProcess.output).length() == 0) {
            return new RootShell.Result(42, "native helper failed: " + nativeStart.output +
                    " | app_process executable not found: " + appProcess.output);
        }
        String appProcessPath = clean(appProcess.output).split("\\s+")[0];
        String apk = context.getApplicationInfo().sourceDir;
        String fallback = "rm -f " + PID + " " + LOG + "; " +
                "(CLASSPATH=" + quote(apk) + " " + quote(appProcessPath) +
                " /system/bin com.tommy.rootdns.RootPort53Forwarder " + proxyPort +
                " >" + LOG + " 2>&1 & echo $! >" + PID + "); " +
                "sleep 2; echo backend=app_process-fallback; echo pid=$(cat " + PID + " 2>/dev/null); cat " + LOG + " 2>/dev/null || true";
        RootShell.Result old = RootShell.run(fallback, 8000);
        return new RootShell.Result(old.code, "native helper failed: " + oneLine(nativeStart.output) + "\n" + old.output);
    }

    private static String stageNativeHelper(Context context, String packaged) {
        FileInputStream in = null;
        FileOutputStream out = null;
        try {
            File external = context.getExternalCacheDir();
            if (external == null) return "";
            File staged = new File(external, "tdns53.bin");
            in = new FileInputStream(packaged);
            out = new FileOutputStream(staged, false);
            byte[] buffer = new byte[16384];
            int n;
            while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
            out.flush();
            staged.setReadable(true, false);
            return staged.getAbsolutePath();
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (in != null) try { in.close(); } catch (Throwable ignored) {}
            if (out != null) try { out.close(); } catch (Throwable ignored) {}
        }
    }

    private static ApplyResult applyBestResolver(ResolverState state) {
        StringBuilder log = new StringBuilder();

        if (state.netId > 0) {
            RootShell.Result net = applyNetId(state.netId);
            log.append("setnetdns[").append(state.netId).append("]: code=")
                    .append(net.code).append(" • ").append(oneLine(net.output)).append('\n');
            if (commandLooksSuccessful(net)) {
                applyPropertiesOnly();
                return new ApplyResult(true, "setnetdns", log.toString());
            }
        } else {
            log.append("setnetdns: skipped (no netId)\n");
        }

        if (state.iface.length() > 0) {
            RootShell.Result legacy = applyLegacyIface(state.iface);
            log.append("legacy resolver[").append(state.iface).append("]: code=")
                    .append(legacy.code).append(" • ").append(oneLine(legacy.output)).append('\n');
            if (commandLooksSuccessful(legacy)) {
                applyPropertiesOnly();
                return new ApplyResult(true, "legacy-iface", log.toString());
            }
        } else {
            log.append("legacy resolver: skipped (no default iface)\n");
        }

        RootShell.Result props = applyPropertiesOnly();
        String p1 = prop("net.dns1");
        String p2 = prop("net.dns2");
        log.append("property resolver: code=").append(props.code).append(" • ")
                .append(oneLine(props.output)).append('\n');
        log.append("property verify: net.dns1=").append(valueOrNone(p1))
                .append(" net.dns2=").append(valueOrNone(p2)).append('\n');
        boolean ok = props.ok() && "127.0.0.1".equals(p1);
        return new ApplyResult(ok, "properties", log.toString());
    }

    private static RootShell.Result applyNetId(int netId) {
        return RootShell.run(
                "ndc resolver setnetdns " + netId + " '' 127.0.0.1 2>&1; " +
                "rc=$?; ndc resolver flushnet " + netId + " >/dev/null 2>&1 || true; exit $rc", 7000);
    }

    private static RootShell.Result applyLegacyIface(String iface) {
        String qif = quote(iface);
        // Netd command syntax changed across Android generations. Try both forms.
        String cmd =
                "out=$(ndc resolver setifdns " + qif + " '' 127.0.0.1 2>&1); rc=$?; " +
                "if [ $rc -ne 0 ] || echo \"$out\" | grep -Eqi 'unknown|failed|error|syntax|wrong number'; then " +
                "  out2=$(ndc resolver setifdns " + qif + " 127.0.0.1 2>&1); rc2=$?; out=\"$out | $out2\"; rc=$rc2; " +
                "fi; " +
                "if [ $rc -eq 0 ]; then out3=$(ndc resolver setdefaultif " + qif + " 2>&1); rc3=$?; out=\"$out | $out3\"; rc=$rc3; fi; " +
                "printf '%s' \"$out\"; exit $rc";
        return RootShell.run(cmd, 7000);
    }

    private static RootShell.Result applyPropertiesOnly() {
        // Legacy Android resolvers reread net.dns* after net.dnschange changes.
        // The CLEAR_DNS_CACHE broadcast mirrors old ConnectivityService behavior.
        String cmd =
                "setprop net.dns1 127.0.0.1; setprop net.dns2 127.0.0.1; " +
                "setprop net.dns3 ''; setprop net.dns4 ''; " +
                "n=$(getprop net.dnschange); case \"$n\" in ''|*[!0-9]*) n=0;; esac; " +
                "n=$((n+1)); setprop net.dnschange \"$n\"; " +
                "am broadcast -a android.intent.action.CLEAR_DNS_CACHE >/dev/null 2>&1 || true; " +
                "printf 'dns1=%s dns2=%s dnschange=%s' \"$(getprop net.dns1)\" \"$(getprop net.dns2)\" \"$(getprop net.dnschange)\"";
        return RootShell.run(cmd, 7000);
    }

    private static void restore(Context context) {
        if (!AppPrefs.resolverHasBackup(context)) return;
        String strategy = AppPrefs.resolverStrategy(context);
        int netId = AppPrefs.resolverNetId(context);
        String iface = clean(AppPrefs.resolverIface(context));
        String dns = clean(AppPrefs.resolverDns(context));
        String domains = clean(AppPrefs.resolverDomains(context));

        if ("setnetdns".equals(strategy) && netId > 0) {
            if (dns.length() > 0) {
                RootShell.run("ndc resolver setnetdns " + netId + " " + quote(domains) + " " + dns +
                        " 2>&1 || true; ndc resolver flushnet " + netId + " 2>&1 || true", 7000);
            } else {
                RootShell.run("ndc resolver clearnetdns " + netId +
                        " 2>&1 || true; ndc resolver flushnet " + netId + " 2>&1 || true", 7000);
            }
        } else if ("legacy-iface".equals(strategy) && iface.length() > 0 && dns.length() > 0) {
            String qif = quote(iface);
            RootShell.run("ndc resolver setifdns " + qif + " " + quote(domains) + " " + dns +
                    " 2>&1 || ndc resolver setifdns " + qif + " " + dns + " 2>&1 || true; " +
                    "ndc resolver setdefaultif " + qif + " 2>&1 || true; " +
                    "ndc resolver flushif " + qif + " 2>&1 || true", 7000);
        }

        String p1 = AppPrefs.resolverProp1(context);
        String p2 = AppPrefs.resolverProp2(context);
        String oldChange = AppPrefs.resolverDnsChange(context);
        String cmd = "setprop net.dns1 " + quote(p1) + "; setprop net.dns2 " + quote(p2) + "; " +
                "setprop net.dns3 ''; setprop net.dns4 ''; ";
        if (oldChange.length() > 0) {
            cmd += "setprop net.dnschange " + quote(oldChange) + "; ";
        } else {
            cmd += "n=$(getprop net.dnschange); case \"$n\" in ''|*[!0-9]*) n=0;; esac; setprop net.dnschange $((n+1)); ";
        }
        cmd += "am broadcast -a android.intent.action.CLEAR_DNS_CACHE >/dev/null 2>&1 || true";
        RootShell.run(cmd, 7000);
    }

    private static void stopHelper() {
        RootShell.run("if [ -f " + PID + " ]; then p=$(cat " + PID + " 2>/dev/null); " +
                "[ -n \"$p\" ] && kill \"$p\" 2>/dev/null || true; fi; rm -f " + PID, 5000);
    }

    private static boolean probeLocalDns53() {
        return probeDnsUdp(53, 8000);
    }

    private static boolean probeDnsUdp(int port, int timeoutMs) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(timeoutMs);
            byte[] query = DnsPackets.aQuery("example.com");
            DatagramPacket p = new DatagramPacket(query, query.length,
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
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

    private static boolean probeDnsTcp(int port, int timeoutMs) {
        java.net.Socket socket = null;
        try {
            byte[] query = DnsPackets.aQuery("example.com");
            socket = new java.net.Socket();
            socket.connect(new InetSocketAddress("127.0.0.1", port), Math.min(timeoutMs, 5000));
            socket.setSoTimeout(timeoutMs);
            java.io.DataOutputStream out = new java.io.DataOutputStream(socket.getOutputStream());
            java.io.DataInputStream in = new java.io.DataInputStream(socket.getInputStream());
            out.writeShort(query.length);
            out.write(query);
            out.flush();
            int len = in.readUnsignedShort();
            if (len < 12 || len > 65535) return false;
            byte[] answer = new byte[len];
            in.readFully(answer);
            return (answer[2] & 0x80) != 0;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (socket != null) try { socket.close(); } catch (Throwable ignored) {}
        }
    }

    private static ResolverState currentState(Context context) {
        int netId = -1;
        String iface = "";
        String dns = "";
        String domains = "";
        String source = "";

        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network network = cm.getActiveNetwork();
                if (network != null) {
                    try {
                        netId = Integer.parseInt(network.toString().trim());
                        source = "ConnectivityManager";
                    } catch (NumberFormatException ignored) {}
                    LinkProperties lp = cm.getLinkProperties(network);
                    if (lp != null) {
                        iface = clean(lp.getInterfaceName());
                        dns = dnsFromLinkProperties(lp);
                        if (lp.getDomains() != null) domains = lp.getDomains();
                    }
                }
            }
        } catch (Throwable ignored) {}

        // Virtual Android often hides getActiveNetwork() from apps while dumpsys still
        // contains the real default network. Parse the default network block, including
        // InterfaceName and DnsAddresses, instead of relying on toolbox awk.
        RootShell.Result dump = RootShell.run("dumpsys connectivity 2>/dev/null | head -n 180 || true", 7000);
        String dumpText = dump.output == null ? "" : dump.output;
        if (netId <= 0) {
            Matcher m = ACTIVE_DEFAULT.matcher(dumpText);
            if (m.find()) {
                try {
                    netId = Integer.parseInt(m.group(1));
                    source = "dumpsys Active default network";
                } catch (Throwable ignored) {}
            } else {
                Matcher wrapped = NETWORK_WRAPPED.matcher(dumpText);
                if (wrapped.find()) {
                    try {
                        netId = Integer.parseInt(wrapped.group(1));
                        source = "dumpsys network{}";
                    } catch (Throwable ignored) {}
                }
            }
        }

        String defaultBlock = dumpText;
        if (netId > 0) {
            int at = dumpText.indexOf("network{" + netId + "}");
            if (at >= 0) defaultBlock = dumpText.substring(at, Math.min(dumpText.length(), at + 5000));
        }
        if (iface.length() == 0) {
            Matcher im = Pattern.compile("InterfaceName:\\s*([A-Za-z0-9_.:-]+)").matcher(defaultBlock);
            if (im.find()) iface = clean(im.group(1));
        }
        if (dns.length() == 0) {
            Matcher dm = Pattern.compile("DnsAddresses:\\s*\\[([^\\]]*)\\]").matcher(defaultBlock);
            if (dm.find()) dns = normalizeDnsList(dm.group(1));
        }
        if (domains.length() == 0) {
            Matcher dom = Pattern.compile("Domains:\\s*([^ }\\r\\n]+)").matcher(defaultBlock);
            if (dom.find() && !"null".equalsIgnoreCase(dom.group(1))) domains = clean(dom.group(1));
        }

        if (iface.length() == 0) {
            RootShell.Result route = RootShell.run("cat /proc/net/route 2>/dev/null || true", 4000);
            iface = defaultIfaceFromRoute(route.output);
            if (iface.length() > 0 && source.length() == 0) source = "/proc/net/route";
        }

        if (dns.length() == 0) {
            String p1 = prop("net.dns1");
            String p2 = prop("net.dns2");
            StringBuilder b = new StringBuilder();
            if (isIpv4(p1)) b.append(p1);
            if (isIpv4(p2) && !p2.equals(p1)) {
                if (b.length() > 0) b.append(' ');
                b.append(p2);
            }
            dns = b.toString();
        }
        if (domains.length() == 0) domains = prop("net.dns.search");
        return new ResolverState(netId, iface, dns, domains, source);
    }

    private static String normalizeDnsList(String raw) {
        if (raw == null) return "";
        StringBuilder out = new StringBuilder();
        for (String part : raw.split("[,\\s]+")) {
            part = clean(part);
            if (!isIpv4(part)) continue;
            if (out.length() > 0) out.append(' ');
            out.append(part);
        }
        return out.toString();
    }

    private static String defaultIfaceFromRoute(String text) {
        if (text == null) return "";
        String[] lines = text.split("\\r?\\n");
        for (int i = 1; i < lines.length; i++) {
            String line = clean(lines[i]);
            if (line.length() == 0) continue;
            String[] fields = line.split("\\s+");
            if (fields.length >= 2 && "00000000".equals(fields[1])) return fields[0];
        }
        return "";
    }

    private static String dnsFromLinkProperties(LinkProperties lp) {
        StringBuilder dns = new StringBuilder();
        Collection<InetAddress> servers = lp.getDnsServers();
        if (servers != null) {
            for (InetAddress a : servers) {
                if (a == null) continue;
                String host = a.getHostAddress();
                if (!isIpv4(host)) continue;
                if (dns.length() > 0) dns.append(' ');
                dns.append(host);
            }
        }
        return dns.toString();
    }

    private static String prop(String name) {
        return clean(RootShell.run("getprop " + name + " 2>/dev/null || true", 4000).output);
    }

    private static boolean commandLooksSuccessful(RootShell.Result result) {
        if (result == null || result.code != 0) return false;
        String value = result.output == null ? "" : result.output;
        String lower = value.toLowerCase();
        if (Pattern.compile("(?m)^\\s*5\\d\\d\\s").matcher(value).find()) return false;
        if (lower.indexOf("failed") >= 0 || lower.indexOf("error") >= 0 ||
                lower.indexOf("unknown command") >= 0 || lower.indexOf("syntax") >= 0 ||
                lower.indexOf("wrong number") >= 0 || lower.indexOf("missing argument") >= 0) return false;
        // netd's command protocol reports success as 2xx; if a numeric protocol status
        // is present, require 2xx instead of trusting the ndc process exit code alone.
        Matcher numeric = Pattern.compile("(?m)^\\s*(\\d{3})\\s").matcher(value);
        if (numeric.find()) {
            try {
                int status = Integer.parseInt(numeric.group(1));
                return status >= 200 && status < 300;
            } catch (Throwable ignored) {}
        }
        return true;
    }

    private static boolean isIpv4(String s) {
        if (s == null || s.length() < 7 || s.indexOf(':') >= 0) return false;
        String[] parts = s.split("\\.");
        if (parts.length != 4) return false;
        for (String part : parts) {
            try {
                int n = Integer.parseInt(part);
                if (n < 0 || n > 255) return false;
            } catch (NumberFormatException e) { return false; }
        }
        return true;
    }

    private static String firstToken(String value) {
        value = clean(value);
        if (value.length() == 0) return "";
        return value.split("\\s+")[0];
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

    private static final class ApplyResult {
        final boolean ok;
        final String method;
        final String log;
        ApplyResult(boolean ok, String method, String log) {
            this.ok = ok;
            this.method = method == null ? "" : method;
            this.log = log == null ? "" : log;
        }
    }

    private static final class ResolverState {
        final int netId;
        final String iface;
        final String dns;
        final String domains;
        final String source;
        ResolverState(int netId, String iface, String dns, String domains, String source) {
            this.netId = netId;
            this.iface = iface == null ? "" : iface;
            this.dns = dns == null ? "" : dns;
            this.domains = domains == null ? "" : domains;
            this.source = source == null ? "" : source;
        }
    }
}
