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
 * v1.9 supports Android 5-7 per-network netd/property resolver stacks and uses a
 * SELinux-aware native root DNS53 helper. It tries several privileged execution paths
 * before considering the optional last-resort permissive compatibility mode. UDP clients
 * on port 53 are translated to the app proxy's proven TCP DNS listener.
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

        // Start localhost:53 before touching Android resolver state. v1.9 is intentionally
        // defensive because vendor root managers may grant uid=0 while keeping the long-lived
        // root shell in a SELinux domain that cannot bind dns_port. startHelper() therefore
        // tries: normal persistent root -> fresh su execution domain -> narrow live policy
        // repair (when a supported policy tool exists) -> momentary permissive bind with
        // immediate re-enforce. No persistent SELinux downgrade happens automatically.
        RootShell.Result helper = startHelper(context, proxyPort);
        out.append("helper start: code=").append(helper.code).append(" • ")
                .append(oneLine(helper.output)).append('\n');
        boolean localUdp = probeDnsUdp(53, 12000);
        boolean localTcp = probeDnsTcp(53, 12000);
        out.append("localhost:53 UDP=").append(localUdp ? "OK" : "FAIL")
                .append(" TCP=").append(localTcp ? "OK" : "FAIL").append('\n');

        if ((!localUdp || !localTcp) && AppPrefs.extremeCompatibility(context)) {
            out.append("safe bind paths exhausted; Extreme compatibility is enabled\n");
            RootShell.Result extreme = startHelperExtreme(context, proxyPort);
            out.append("extreme helper start: code=").append(extreme.code).append(" • ")
                    .append(oneLine(extreme.output)).append('\n');
            localUdp = probeDnsUdp(53, 12000);
            localTcp = probeDnsTcp(53, 12000);
            out.append("localhost:53 after extreme compatibility UDP=")
                    .append(localUdp ? "OK" : "FAIL").append(" TCP=")
                    .append(localTcp ? "OK" : "FAIL").append('\n');
        }

        if (!localUdp || !localTcp) {
            out.append("ERROR: localhost:53 bridge did not answer both UDP and TCP DNS\n");
            if (!AppPrefs.extremeCompatibility(context)) {
                out.append("Extreme compatibility is OFF. It is intentionally opt-in because it may keep SELinux Permissive while DNS is active.\n");
            }
            RootShell.Result details = RootShell.run("cat " + LOG + " 2>/dev/null || true", 4000);
            if (details.output.length() > 0) out.append(details.output).append('\n');
            stopHelper();
            restoreSelinux(context);
            return new RootShell.Result(43, out.toString());
        }
        out.append("localhost:53 DNS bridge=OK\n");

        ApplyResult applied = applyBestResolver(state);
        out.append(applied.log);
        if (!applied.ok) {
            restore(context);
            stopHelper();
            restoreSelinux(context);
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
        restoreSelinux(context);
        AppPrefs.clearResolverBackup(context);
    }

    static void emergencyRestoreSecurity(Context context) {
        restoreSelinux(context);
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
        RootShell.Result se = RootShell.run("echo mode=$(getenforce 2>/dev/null || echo Unknown); echo ctx=$(cat /proc/$$/attr/current 2>/dev/null || echo unknown); for p in magiskpolicy supolicy /sbin/magiskpolicy /sbin/supolicy /data/adb/magisk/magiskpolicy; do command -v \"$p\" 2>/dev/null || [ -x \"$p\" ] && echo \"$p\"; done", 5000);
        out.append("SELinux/root context: ").append(valueOrNone(oneLine(se.output))).append('\n');
        out.append("extreme compatibility: ").append(AppPrefs.extremeCompatibility(context) ? "enabled" : "disabled").append('\n');
        out.append("SELinux relaxed by Tommy: ").append(AppPrefs.selinuxRelaxed(context) ? "yes" : "no").append('\n');
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
        RootShell.Result avc = recentAvc();
        out.append("recent AVC: ").append(valueOrNone(oneLine(avc.output))).append('\n');
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
        restoreSelinux(context);

        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        String packaged = nativeDir == null ? "" : nativeDir + "/libtdns53.so";
        if (packaged.length() == 0) {
            return new RootShell.Result(42, "nativeLibraryDir unavailable");
        }
        String staged = stageNativeHelper(context, packaged);
        String prep = nativeStartCommand(packaged, staged, proxyPort);
        StringBuilder log = new StringBuilder();

        RootShell.Result direct = RootShell.run(prep, 14000);
        log.append("attempt[persistent-root]: code=").append(direct.code).append(" • ")
                .append(oneLine(direct.output)).append('\n');
        if (direct.ok()) return new RootShell.Result(0, log.toString());

        boolean bindDenied = isBindPermissionDenied(direct.output);
        if (bindDenied) {
            // A fresh su can run in a different SELinux domain than `su -c sh` on vendor roots.
            // It costs at most one extra root-manager grant toast, but only on this EACCES path.
            stopHelper();
            RootShell.Result fresh = RootShell.runFreshSu(prep, 14000);
            log.append("attempt[fresh-su-domain]: code=").append(fresh.code).append(" • ")
                    .append(oneLine(fresh.output)).append('\n');
            if (fresh.ok()) return new RootShell.Result(0, log.toString());

            // If Magisk/SuperSU exposes a live policy tool, repair only the DNS-port bind
            // permissions for the current root domain rather than disabling SELinux globally.
            RootShell.Result patch = tryLivePolicyPatch(direct.output + "\n" + fresh.output);
            log.append("attempt[narrow-sepolicy-repair]: code=").append(patch.code).append(" • ")
                    .append(oneLine(patch.output)).append('\n');
            if (patch.ok()) {
                stopHelper();
                RootShell.Result afterPatch = RootShell.run(prep, 14000);
                log.append("attempt[after-policy-repair]: code=").append(afterPatch.code).append(" • ")
                        .append(oneLine(afterPatch.output)).append('\n');
                if (afterPatch.ok()) return new RootShell.Result(0, log.toString());
            }

            // Last safe automatic attempt: disable enforcing only long enough for bind()/listen()
            // to complete, then immediately restore Enforcing before returning to app code.
            // If ongoing traffic is permitted after the socket exists, no persistent downgrade
            // is needed. The caller probes UDP+TCP after Enforcing has already been restored.
            stopHelper();
            RootShell.Result transientBind = RootShell.run(transientPermissiveStartCommand(prep), 18000);
            log.append("attempt[transient-permissive-bind]: code=").append(transientBind.code).append(" • ")
                    .append(oneLine(transientBind.output)).append('\n');
            if (transientBind.ok()) return new RootShell.Result(0, log.toString());
        }

        // app_process remains useful only when the native executable itself cannot run. It is
        // intentionally NOT used to mask an SELinux dns_port denial, because it inherits a
        // similarly restricted domain on this virtual Android and only adds noise.
        if (!bindDenied && direct.output.indexOf("START native") < 0) {
            RootShell.Result old = startAppProcessFallback(context, proxyPort);
            log.append("attempt[app_process-exec-fallback]: code=").append(old.code).append(" • ")
                    .append(oneLine(old.output)).append('\n');
            if (old.ok()) return new RootShell.Result(0, log.toString());
        }

        RootShell.Result avc = recentAvc();
        log.append("recent AVC: ").append(oneLine(avc.output)).append('\n');
        return new RootShell.Result(42, log.toString());
    }

    private static RootShell.Result startHelperExtreme(Context context, int proxyPort) {
        stopHelper();
        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        String packaged = nativeDir == null ? "" : nativeDir + "/libtdns53.so";
        if (packaged.length() == 0) return new RootShell.Result(62, "nativeLibraryDir unavailable");
        String staged = stageNativeHelper(context, packaged);
        String prep = nativeStartCommand(packaged, staged, proxyPort);
        int appPid = android.os.Process.myPid();

        RootShell.Result current = RootShell.run("getenforce 2>/dev/null || echo Unknown", 4000);
        String mode = clean(current.output);
        boolean changed = "Enforcing".equalsIgnoreCase(mode);
        if (changed) {
            RootShell.Result relax = RootShell.run("setenforce 0 2>&1; rc=$?; echo mode=$(getenforce 2>/dev/null); exit $rc", 5000);
            if (!relax.ok() || oneLine(relax.output).toLowerCase().indexOf("permissive") < 0) {
                return new RootShell.Result(63, "cannot enter Permissive: " + relax.output);
            }
            AppPrefs.selinuxRelaxed(context, true);
        }

        RootShell.Result started = RootShell.run(prep, 14000);
        if (!started.ok()) {
            if (changed) restoreSelinux(context);
            return new RootShell.Result(started.code, "Permissive helper failed: " + started.output);
        }

        if (changed) {
            // Root watchdog is independent of the APK process. If either Tommy's app process or
            // the DNS helper disappears unexpectedly, it kills the helper and restores Enforcing.
            String watchdog =
                    "hp=$(cat " + quote(PID) + " 2>/dev/null); " +
                    "( while [ -d /proc/" + appPid + " ] && [ -n \"$hp\" ] && kill -0 \"$hp\" 2>/dev/null; do sleep 2; done; " +
                    "[ -n \"$hp\" ] && kill \"$hp\" 2>/dev/null || true; setenforce 1 2>/dev/null || true ) >/dev/null 2>&1 &";
            RootShell.run(watchdog, 4000);
        }
        return new RootShell.Result(0, "SELinux mode before=" + valueOrNone(mode) + " kept=Permissive while active; " + started.output);
    }

    private static String nativeStartCommand(String packaged, String staged, int proxyPort) {
        String qsrc = quote(packaged);
        String qstage = staged.length() == 0 ? "''" : quote(staged);
        return
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
    }

    private static String transientPermissiveStartCommand(String prep) {
        return "orig=$(getenforce 2>/dev/null || echo Unknown); echo SELinux-before=$orig; " +
                "if [ \"$orig\" = Enforcing ]; then setenforce 0 2>&1 || exit 60; fi; " +
                "( " + prep + " ); rc=$?; " +
                "if [ \"$orig\" = Enforcing ]; then setenforce 1 2>&1 || true; fi; " +
                "echo SELinux-after=$(getenforce 2>/dev/null || echo Unknown); exit $rc";
    }

    private static RootShell.Result tryLivePolicyPatch(String helperOutput) {
        String helperContext = helperContext(helperOutput);
        String domain = selinuxType(helperContext);
        if (domain.length() == 0) {
            RootShell.Result ctxResult = RootShell.run("cat /proc/$$/attr/current 2>/dev/null || true", 4000);
            helperContext = clean(ctxResult.output);
            domain = selinuxType(helperContext);
        }

        RootShell.Result toolResult = RootShell.run(
                "for p in magiskpolicy supolicy /sbin/magiskpolicy /sbin/supolicy /data/adb/magisk/magiskpolicy; do " +
                "command -v \"$p\" >/dev/null 2>&1 && { command -v \"$p\"; exit 0; }; [ -x \"$p\" ] && { echo \"$p\"; exit 0; }; done; exit 1", 4000);
        String tool = firstToken(toolResult.output);
        if (domain.length() == 0 || tool.length() == 0) {
            return new RootShell.Result(61, "helper-context=" + valueOrNone(helperContext) +
                    " policy-tool=" + valueOrNone(tool));
        }

        String qt = quote(tool);
        StringBuilder cmd = new StringBuilder();
        cmd.append("ok=0; ");
        // On AOSP-style policy, netdomain already carries most socket permissions. Some vendor
        // roots drop that attribute from their root/shell domain, so restore it when the policy
        // engine supports live typeattribute changes. Failure is harmless; exact rules follow.
        appendPolicy(cmd, qt, "typeattribute " + domain + " netdomain", false);
        appendPolicy(cmd, qt, "allow " + domain + " dns_port udp_socket name_bind", true);
        appendPolicy(cmd, qt, "allow " + domain + " dns_port tcp_socket name_bind", true);
        appendPolicy(cmd, qt, "allow " + domain + " unreserved_port tcp_socket name_connect", true);
        appendPolicy(cmd, qt, "allow " + domain + " node udp_socket node_bind", false);
        appendPolicy(cmd, qt, "allow " + domain + " node tcp_socket node_bind", false);
        appendPolicy(cmd, qt, "allow " + domain + " loopback_node udp_socket node_bind", false);
        appendPolicy(cmd, qt, "allow " + domain + " loopback_node tcp_socket node_bind", false);
        appendPolicy(cmd, qt, "allow " + domain + " " + domain + " udp_socket { create ioctl read write getattr setopt getopt bind connect sendto recvfrom shutdown }", false);
        appendPolicy(cmd, qt, "allow " + domain + " " + domain + " tcp_socket { create ioctl read write getattr setopt getopt bind listen accept connect shutdown }", false);

        // Use actual AVC denials as a second source of truth. Only network socket classes and a
        // conservative permission whitelist are accepted, and only when the denial's source type
        // is exactly the helper's domain. This lets the same build adapt to vendor-specific policy
        // without turning unrelated denials into blanket allow rules.
        RootShell.Result avc = recentAvc();
        String[] lines = avc.output == null ? new String[0] : avc.output.split("\\r?\\n");
        int avcRules = 0;
        for (String line : lines) {
            PolicyDenial denial = parseNetworkDenial(line, domain);
            if (denial == null) continue;
            appendPolicy(cmd, qt, "allow " + domain + " " + denial.targetType + " " + denial.tclass +
                    " { " + denial.permissions + " }", true);
            avcRules++;
            if (avcRules >= 8) break;
        }
        cmd.append("echo policy_tool=").append(qt).append(" domain=").append(quote(domain))
                .append(" avc_rules=").append(avcRules).append(" applied=$ok; [ $ok -eq 1 ]");
        RootShell.Result applied = RootShell.run(cmd.toString(), 10000);
        return new RootShell.Result(applied.code,
                "helper-context=" + helperContext + " " + applied.output);
    }

    private static void appendPolicy(StringBuilder cmd, String quotedTool, String statement, boolean countsAsSuccess) {
        cmd.append(quotedTool).append(" --live ").append(quote(statement)).append(" >/dev/null 2>&1");
        if (countsAsSuccess) cmd.append(" && ok=1");
        cmd.append(" || true; ");
    }

    private static String helperContext(String output) {
        if (output == null) return "";
        Matcher m = Pattern.compile("context=([^\\s]+)").matcher(output);
        String last = "";
        while (m.find()) last = clean(m.group(1));
        return last;
    }

    private static PolicyDenial parseNetworkDenial(String line, String expectedSource) {
        if (line == null || line.toLowerCase().indexOf("avc:") < 0 || line.toLowerCase().indexOf("denied") < 0) return null;
        Matcher perms = Pattern.compile("denied\\s*\\{([^}]*)\\}", Pattern.CASE_INSENSITIVE).matcher(line);
        Matcher src = Pattern.compile("scontext=[^: \t]+:[^: \t]+:([^: \t]+):[^ \t]+", Pattern.CASE_INSENSITIVE).matcher(line);
        Matcher tgt = Pattern.compile("tcontext=[^: \t]+:[^: \t]+:([^: \t]+):[^ \t]+", Pattern.CASE_INSENSITIVE).matcher(line);
        Matcher cls = Pattern.compile("tclass=([A-Za-z0-9_]+)", Pattern.CASE_INSENSITIVE).matcher(line);
        if (!perms.find() || !src.find() || !tgt.find() || !cls.find()) return null;
        String source = clean(src.group(1));
        String target = clean(tgt.group(1));
        String tclass = clean(cls.group(1));
        if (!expectedSource.equals(source) || !networkClass(tclass)) return null;
        StringBuilder allowed = new StringBuilder();
        for (String p : perms.group(1).trim().split("\\s+")) {
            p = p.replaceAll("[^A-Za-z0-9_]", "");
            if (!networkPermission(p)) continue;
            if (allowed.length() > 0) allowed.append(' ');
            allowed.append(p);
        }
        if (allowed.length() == 0 || target.length() == 0) return null;
        return new PolicyDenial(target, tclass, allowed.toString());
    }

    private static boolean networkClass(String c) {
        return "udp_socket".equals(c) || "tcp_socket".equals(c) || "rawip_socket".equals(c) ||
                "netlink_route_socket".equals(c) || "sock_file".equals(c);
    }

    private static boolean networkPermission(String p) {
        String all = " accept append bind connect create getattr getopt ioctl listen lock name_bind name_connect node_bind open read recvfrom recv_msg send_msg sendto setattr setopt shutdown unlink write map ";
        return p.length() > 0 && all.indexOf(" " + p + " ") >= 0;
    }

    private static RootShell.Result startAppProcessFallback(Context context, int proxyPort) {
        RootShell.Result appProcess = RootShell.run(
                "for p in /system/bin/app_process /system/bin/app_process64 /system/bin/app_process32; do " +
                "[ -x \"$p\" ] && { echo \"$p\"; exit 0; }; done; exit 1", 5000);
        if (!appProcess.ok() || clean(appProcess.output).length() == 0) {
            return new RootShell.Result(42, "app_process executable not found: " + appProcess.output);
        }
        String appProcessPath = clean(appProcess.output).split("\\s+")[0];
        String apk = context.getApplicationInfo().sourceDir;
        String fallback = "rm -f " + PID + " " + LOG + "; " +
                "(CLASSPATH=" + quote(apk) + " " + quote(appProcessPath) +
                " /system/bin com.tommy.rootdns.RootPort53Forwarder " + proxyPort +
                " >" + LOG + " 2>&1 & echo $! >" + PID + "); " +
                "sleep 2; echo backend=app_process-exec-fallback; echo pid=$(cat " + PID + " 2>/dev/null); cat " + LOG + " 2>/dev/null || true";
        return RootShell.run(fallback, 8000);
    }

    private static boolean isBindPermissionDenied(String output) {
        String lower = output == null ? "" : output.toLowerCase();
        return lower.indexOf("permission denied") >= 0 || lower.indexOf("errno=13") >= 0;
    }

    private static String selinuxType(String context) {
        context = clean(context);
        String[] parts = context.split(":");
        if (parts.length >= 3) {
            String type = parts[2].replaceAll("[^A-Za-z0-9_]", "");
            return type;
        }
        return "";
    }

    private static RootShell.Result recentAvc() {
        return RootShell.run(
                "(dmesg 2>/dev/null || true; logcat -b all -d 2>/dev/null || true) | grep -i 'avc:.*denied' | tail -n 8 || true", 7000);
    }

    private static void restoreSelinux(Context context) {
        if (!AppPrefs.selinuxRelaxed(context)) return;
        RootShell.run("setenforce 1 2>/dev/null || true", 5000);
        AppPrefs.selinuxRelaxed(context, false);
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
            int before = helperQueryCount();
            RootShell.Result net = applyNetId(state.netId);
            log.append("setnetdns[").append(state.netId).append("]: code=")
                    .append(net.code).append(" • ").append(oneLine(net.output)).append('\n');
            if (commandLooksSuccessful(net)) {
                boolean verified = verifySystemResolverThroughBridge(before);
                log.append("setnetdns behavioral verify: ").append(verified ? "BRIDGE_HIT" : "NO_BRIDGE_HIT").append('\n');
                if (verified) {
                    applyPropertiesOnly();
                    return new ApplyResult(true, "setnetdns", log.toString());
                }
            }
        } else {
            log.append("setnetdns: skipped (no netId)\n");
        }

        if (state.iface.length() > 0) {
            int before = helperQueryCount();
            RootShell.Result legacy = applyLegacyIface(state.iface);
            log.append("legacy resolver[").append(state.iface).append("]: code=")
                    .append(legacy.code).append(" • ").append(oneLine(legacy.output)).append('\n');
            if (commandLooksSuccessful(legacy)) {
                boolean verified = verifySystemResolverThroughBridge(before);
                log.append("legacy behavioral verify: ").append(verified ? "BRIDGE_HIT" : "NO_BRIDGE_HIT").append('\n');
                if (verified) {
                    applyPropertiesOnly();
                    return new ApplyResult(true, "legacy-iface", log.toString());
                }
            }
        } else {
            log.append("legacy resolver: skipped (no default iface)\n");
        }

        int before = helperQueryCount();
        RootShell.Result props = applyPropertiesOnly();
        String p1 = prop("net.dns1");
        String p2 = prop("net.dns2");
        log.append("property resolver: code=").append(props.code).append(" • ")
                .append(oneLine(props.output)).append('\n');
        log.append("property verify: net.dns1=").append(valueOrNone(p1))
                .append(" net.dns2=").append(valueOrNone(p2)).append('\n');
        boolean propertyValues = props.ok() && "127.0.0.1".equals(p1);
        boolean behavioral = propertyValues && verifySystemResolverThroughBridge(before);
        log.append("property behavioral verify: ").append(behavioral ? "BRIDGE_HIT" : "NO_BRIDGE_HIT").append('\n');
        return new ApplyResult(behavioral, "properties", log.toString());
    }

    private static int helperQueryCount() {
        RootShell.Result r = RootShell.run("grep -c '^QUERY ' " + quote(LOG) + " 2>/dev/null || echo 0", 4000);
        String value = clean(r.output);
        if (value.indexOf('\n') >= 0) value = value.substring(value.lastIndexOf('\n') + 1).trim();
        try { return Integer.parseInt(value); }
        catch (Throwable ignored) { return 0; }
    }

    private static boolean verifySystemResolverThroughBridge(int beforeCount) {
        String name = "tdns-check-" + Long.toHexString(System.nanoTime()) + ".example.com";
        try {
            InetAddress.getByName(name);
        } catch (Throwable ignored) {
            // NXDOMAIN is fine. The only thing being verified is whether the system resolver's
            // query traversed the local bridge, not whether the random hostname exists.
        }
        int after = helperQueryCount();
        return after > beforeCount;
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

    private static final class PolicyDenial {
        final String targetType;
        final String tclass;
        final String permissions;
        PolicyDenial(String targetType, String tclass, String permissions) {
            this.targetType = targetType;
            this.tclass = tclass;
            this.permissions = permissions;
        }
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
