package com.tommy.rootdns;

final class IptablesManager {
    private static final String CHAIN = "TOMMY_DNS";
    private static final String PROBE_CHAIN = "TOMMY_PROBE";

    private static final String[] IPTABLES = new String[] {
            "/system/bin/iptables",
            "/system/xbin/iptables",
            "/vendor/bin/iptables",
            "/sbin/iptables",
            "/su/bin/iptables",
            "iptables",
            "busybox iptables"
    };

    private static final String[] IP6TABLES = new String[] {
            "/system/bin/ip6tables",
            "/system/xbin/ip6tables",
            "/vendor/bin/ip6tables",
            "/sbin/ip6tables",
            "/su/bin/ip6tables",
            "ip6tables",
            "busybox ip6tables"
    };

    private IptablesManager() {}

    static RootShell.Result enable(int appUid, int proxyPort) {
        // appUid is intentionally retained in the method signature for source/API stability.
        // DNS interception only matches destination port 53, while this app's DoH traffic is
        // HTTPS/443, so xt_owner is not required. Avoiding xt_owner improves old-kernel support.
        StringBuilder log = new StringBuilder();
        log.append("TommyRootDNS iptables enable\n");
        log.append("proxy=127.0.0.1:").append(proxyPort).append('\n');

        // Remove stale rules left by an older build before choosing a backend.
        disable();

        int lastCode = 20;
        for (int i = 0; i < IPTABLES.length; i++) {
            String ipt = IPTABLES[i];
            RootShell.Result version = RootShell.run(ipt + " --version", 5000);
            append(log, "backend " + ipt + " --version", version);
            if (!version.ok()) {
                lastCode = version.code;
                continue;
            }

            RootShell.Result nat = RootShell.run(ipt + " -t nat -L OUTPUT -n", 7000);
            append(log, "nat OUTPUT access", nat);
            if (!nat.ok()) {
                log.append("ERROR: NAT unavailable with ").append(ipt).append(": ")
                        .append(oneLine(nat.output)).append('\n');
                lastCode = nat.code;
                continue;
            }

            RootShell.Result chain = prepareChain(ipt, CHAIN, log);
            if (chain.ok()) {
                RootShell.Result rules = installInChain(ipt, proxyPort, log);
                if (rules.ok()) {
                    String ipv6 = enableIpv6BestEffort(proxyPort, log);
                    log.append("IPV4_OK\nBACKEND=").append(ipt)
                            .append("\nMODE=CHAIN\nTARGET=").append(extractMarker(rules.output, "TARGET="))
                            .append('\n');
                    if (ipv6.length() > 0) log.append(ipv6).append('\n');
                    return new RootShell.Result(0, log.toString().trim());
                }
                lastCode = rules.code;
                cleanCandidate(ipt, proxyPort);
            } else {
                lastCode = chain.code;
            }

            // Some vendor builds permit OUTPUT NAT rules but behave badly with custom chains.
            // Try exact direct OUTPUT rules as a compatibility fallback.
            RootShell.Result direct = installDirect(ipt, proxyPort, log);
            if (direct.ok()) {
                String ipv6 = enableIpv6BestEffort(proxyPort, log);
                log.append("IPV4_OK\nBACKEND=").append(ipt)
                        .append("\nMODE=DIRECT\nTARGET=").append(extractMarker(direct.output, "TARGET="))
                        .append('\n');
                if (ipv6.length() > 0) log.append(ipv6).append('\n');
                return new RootShell.Result(0, log.toString().trim());
            }
            lastCode = direct.code;
            cleanCandidate(ipt, proxyPort);
        }

        log.append("SUMMARY: no compatible IPv4 iptables NAT backend could install DNS interception\n");
        return new RootShell.Result(lastCode == 0 ? 20 : lastCode, log.toString().trim());
    }

    static RootShell.Result disable() {
        StringBuilder log = new StringBuilder();
        int firstFailure = 0;
        for (int i = 0; i < IPTABLES.length; i++) {
            RootShell.Result r = cleanCandidate(IPTABLES[i], BuildConfig.DNS_PROXY_PORT);
            if (!r.ok() && firstFailure == 0) firstFailure = r.code;
        }
        for (int i = 0; i < IP6TABLES.length; i++) {
            RootShell.Result r = cleanIpv6Candidate(IP6TABLES[i]);
            if (!r.ok() && firstFailure == 0) firstFailure = r.code;
        }
        log.append("CLEAN");
        // Cleanup is intentionally best effort: missing binaries/chains are normal.
        return new RootShell.Result(0, log.toString());
    }

    static String probe(int proxyPort) {
        StringBuilder log = new StringBuilder();
        log.append("=== IPTABLES PROBE ===\n");
        boolean found = false;
        for (int i = 0; i < IPTABLES.length; i++) {
            String ipt = IPTABLES[i];
            RootShell.Result version = RootShell.run(ipt + " --version", 5000);
            log.append("\n[").append(ipt).append("]\n");
            log.append("version: ").append(resultShort(version)).append('\n');
            if (!version.ok()) continue;
            found = true;

            RootShell.Result filter = RootShell.run(ipt + " -L OUTPUT -n", 7000);
            log.append("filter OUTPUT: ").append(resultShort(filter)).append('\n');
            RootShell.Result nat = RootShell.run(ipt + " -t nat -L OUTPUT -n", 7000);
            log.append("nat OUTPUT: ").append(resultShort(nat)).append('\n');
            if (!nat.ok()) continue;

            RootShell.run("while " + ipt + " -t nat -D OUTPUT -j " + PROBE_CHAIN + " 2>/dev/null; do :; done; true", 5000);
            RootShell.run(ipt + " -t nat -F " + PROBE_CHAIN + " 2>/dev/null || true; " +
                    ipt + " -t nat -X " + PROBE_CHAIN + " 2>/dev/null || true", 5000);

            RootShell.Result create = RootShell.run(ipt + " -t nat -N " + PROBE_CHAIN, 7000);
            log.append("create chain: ").append(resultShort(create)).append('\n');
            if (create.ok()) {
                RootShell.Result redirUdp = RootShell.run(ipt + " -t nat -A " + PROBE_CHAIN +
                        " -p udp --dport 53 -j REDIRECT --to-ports " + proxyPort, 7000);
                log.append("REDIRECT udp/53: ").append(resultShort(redirUdp)).append('\n');
                RootShell.Result redirTcp = RootShell.run(ipt + " -t nat -A " + PROBE_CHAIN +
                        " -p tcp --dport 53 -j REDIRECT --to-ports " + proxyPort, 7000);
                log.append("REDIRECT tcp/53: ").append(resultShort(redirTcp)).append('\n');
                RootShell.run(ipt + " -t nat -F " + PROBE_CHAIN + " 2>/dev/null || true; " +
                        ipt + " -t nat -X " + PROBE_CHAIN + " 2>/dev/null || true", 5000);
            }
        }
        if (!found) log.append("\nNo working iptables binary was found.\n");

        log.append("\n=== IP6TABLES PROBE ===\n");
        boolean found6 = false;
        for (int i = 0; i < IP6TABLES.length; i++) {
            String ip6 = IP6TABLES[i];
            RootShell.Result version = RootShell.run(ip6 + " --version", 5000);
            if (!version.ok()) continue;
            found6 = true;
            log.append('[').append(ip6).append("] ").append(oneLine(version.output)).append('\n');
            RootShell.Result nat = RootShell.run(ip6 + " -t nat -L OUTPUT -n", 7000);
            log.append("IPv6 nat OUTPUT: ").append(resultShort(nat)).append('\n');
            break;
        }
        if (!found6) log.append("No working ip6tables binary was found.\n");
        return log.toString().trim();
    }

    static String failureSummary(RootShell.Result result) {
        if (result == null) return "unknown error";
        String[] lines = result.output.split("\\r?\\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (line.startsWith("ERROR:")) return line.substring(6).trim();
        }
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (line.startsWith("SUMMARY:")) return line.substring(8).trim();
        }
        String one = oneLine(result.output);
        return one.length() == 0 ? "exit " + result.code : one;
    }

    private static RootShell.Result prepareChain(String ipt, String chain, StringBuilder log) {
        RootShell.Result flush = RootShell.run(ipt + " -t nat -F " + chain, 7000);
        if (flush.ok()) {
            append(log, "reuse chain " + chain, flush);
            detachChain(ipt, chain);
            return flush;
        }

        append(log, "flush existing chain " + chain, flush);
        RootShell.Result create = RootShell.run(ipt + " -t nat -N " + chain, 7000);
        append(log, "create chain " + chain, create);
        if (!create.ok()) {
            log.append("ERROR: cannot create/flush ").append(chain).append(" with ").append(ipt)
                    .append(": ").append(oneLine(create.output)).append('\n');
            return create;
        }
        detachChain(ipt, chain);
        return create;
    }

    private static RootShell.Result installInChain(String ipt, int proxyPort, StringBuilder log) {
        RootShell.Result redirect = addPair(ipt, CHAIN, proxyPort, "REDIRECT", false, log);
        if (!redirect.ok()) {
            RootShell.run(ipt + " -t nat -F " + CHAIN + " 2>/dev/null || true", 5000);
            RootShell.Result dnat = addPair(ipt, CHAIN, proxyPort, "DNAT", false, log);
            if (!dnat.ok()) return dnat;
            redirect = dnat;
        }

        RootShell.Result attach = RootShell.run(ipt + " -t nat -I OUTPUT 1 -j " + CHAIN, 7000);
        append(log, "attach OUTPUT -> " + CHAIN, attach);
        if (!attach.ok()) {
            log.append("ERROR: cannot attach ").append(CHAIN).append(" to OUTPUT: ")
                    .append(oneLine(attach.output)).append('\n');
            return new RootShell.Result(24, attach.output);
        }

        RootShell.Result verify = RootShell.run(ipt + " -t nat -L " + CHAIN + " -n", 7000);
        append(log, "verify chain", verify);
        if (!verify.ok()) return new RootShell.Result(25, verify.output);
        return redirect;
    }

    private static RootShell.Result installDirect(String ipt, int proxyPort, StringBuilder log) {
        cleanDirectRules(ipt, proxyPort);
        RootShell.Result redirect = addPair(ipt, "OUTPUT", proxyPort, "REDIRECT", true, log);
        if (redirect.ok()) return redirect;

        cleanDirectRules(ipt, proxyPort);
        RootShell.Result dnat = addPair(ipt, "OUTPUT", proxyPort, "DNAT", true, log);
        if (dnat.ok()) return dnat;
        cleanDirectRules(ipt, proxyPort);
        return dnat;
    }

    private static RootShell.Result addPair(String ipt, String chain, int proxyPort,
                                             String target, boolean direct, StringBuilder log) {
        String suffix;
        if ("DNAT".equals(target)) {
            suffix = " -j DNAT --to-destination 127.0.0.1:" + proxyPort;
        } else {
            suffix = " -j REDIRECT --to-ports " + proxyPort;
        }

        RootShell.Result udp = RootShell.run(ipt + " -t nat -A " + chain +
                " -p udp --dport 53" + suffix, 7000);
        append(log, (direct ? "direct " : "chain ") + target + " udp/53", udp);
        if (!udp.ok()) {
            log.append("ERROR: ").append(target).append(" udp/53 failed: ")
                    .append(oneLine(udp.output)).append('\n');
            return new RootShell.Result(22, udp.output);
        }

        RootShell.Result tcp = RootShell.run(ipt + " -t nat -A " + chain +
                " -p tcp --dport 53" + suffix, 7000);
        append(log, (direct ? "direct " : "chain ") + target + " tcp/53", tcp);
        if (!tcp.ok()) {
            log.append("ERROR: ").append(target).append(" tcp/53 failed: ")
                    .append(oneLine(tcp.output)).append('\n');
            return new RootShell.Result(23, tcp.output);
        }
        return new RootShell.Result(0, "TARGET=" + target);
    }

    private static String enableIpv6BestEffort(int proxyPort, StringBuilder log) {
        for (int i = 0; i < IP6TABLES.length; i++) {
            String ip6 = IP6TABLES[i];
            RootShell.Result version = RootShell.run(ip6 + " --version", 4000);
            if (!version.ok()) continue;
            RootShell.Result nat = RootShell.run(ip6 + " -t nat -L OUTPUT -n", 6000);
            append(log, "IPv6 nat access " + ip6, nat);
            if (!nat.ok()) continue;

            RootShell.Result chain = prepareChain(ip6, CHAIN, log);
            if (!chain.ok()) continue;
            RootShell.Result pair = addPair(ip6, CHAIN, proxyPort, "REDIRECT", false, log);
            if (!pair.ok()) {
                cleanIpv6Candidate(ip6);
                continue;
            }
            RootShell.Result attach = RootShell.run(ip6 + " -t nat -I OUTPUT 1 -j " + CHAIN, 6000);
            append(log, "IPv6 attach", attach);
            if (attach.ok()) return "IPV6_OK\nIPV6_BACKEND=" + ip6;
            cleanIpv6Candidate(ip6);
        }
        return "";
    }

    private static RootShell.Result cleanCandidate(String ipt, int proxyPort) {
        String script =
                "while " + ipt + " -t nat -D OUTPUT -j " + CHAIN + " 2>/dev/null; do :; done; " +
                "" + ipt + " -t nat -F " + CHAIN + " 2>/dev/null || true; " +
                "" + ipt + " -t nat -X " + CHAIN + " 2>/dev/null || true; " +
                directDeleteScript(ipt, proxyPort) +
                "true";
        return RootShell.run(script, 9000);
    }

    private static RootShell.Result cleanIpv6Candidate(String ip6) {
        String script =
                "while " + ip6 + " -t nat -D OUTPUT -j " + CHAIN + " 2>/dev/null; do :; done; " +
                ip6 + " -t nat -F " + CHAIN + " 2>/dev/null || true; " +
                ip6 + " -t nat -X " + CHAIN + " 2>/dev/null || true; true";
        return RootShell.run(script, 7000);
    }

    private static void cleanDirectRules(String ipt, int proxyPort) {
        RootShell.run(directDeleteScript(ipt, proxyPort) + "true", 7000);
    }

    private static String directDeleteScript(String ipt, int proxyPort) {
        return
                "while " + ipt + " -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports " + proxyPort + " 2>/dev/null; do :; done; " +
                "while " + ipt + " -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports " + proxyPort + " 2>/dev/null; do :; done; " +
                "while " + ipt + " -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:" + proxyPort + " 2>/dev/null; do :; done; " +
                "while " + ipt + " -t nat -D OUTPUT -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:" + proxyPort + " 2>/dev/null; do :; done; ";
    }

    private static void detachChain(String ipt, String chain) {
        RootShell.run("while " + ipt + " -t nat -D OUTPUT -j " + chain + " 2>/dev/null; do :; done; true", 5000);
    }

    private static void append(StringBuilder log, String label, RootShell.Result result) {
        log.append(label).append(": code=").append(result.code);
        String shortOut = oneLine(result.output);
        if (shortOut.length() > 0) log.append(" • ").append(shortOut);
        log.append('\n');
    }

    private static String resultShort(RootShell.Result result) {
        String out = oneLine(result.output);
        if (out.length() > 180) out = out.substring(0, 180) + "…";
        return "code=" + result.code + (out.length() == 0 ? "" : " • " + out);
    }

    private static String oneLine(String value) {
        if (value == null) return "";
        String v = value.trim().replace('\r', ' ').replace('\n', ' ');
        while (v.indexOf("  ") >= 0) v = v.replace("  ", " ");
        if (v.length() > 260) v = v.substring(0, 260) + "…";
        return v;
    }

    private static String extractMarker(String value, String marker) {
        if (value == null) return "UNKNOWN";
        int pos = value.indexOf(marker);
        if (pos < 0) return "UNKNOWN";
        String out = value.substring(pos + marker.length()).trim();
        int nl = out.indexOf('\n');
        if (nl >= 0) out = out.substring(0, nl).trim();
        return out.length() == 0 ? "UNKNOWN" : out;
    }
}
