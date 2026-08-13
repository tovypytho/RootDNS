package com.tommy.rootdns;

final class IptablesManager {
    private static final String CHAIN = "TOMMY_DNS";

    private IptablesManager() {}

    static RootShell.Result enable(int appUid, int proxyPort) {
        // The proxy bootstraps its DoH hostname before these rules are installed and then
        // connects to the cached IP with TLS SNI, so xt_owner is only a best-effort extra guard.
        String script =
                "IPT=$(command -v iptables 2>/dev/null || echo iptables); " +
                "$IPT -t nat -N " + CHAIN + " 2>/dev/null || true; " +
                "$IPT -t nat -F " + CHAIN + " || exit 20; " +
                "while $IPT -t nat -D OUTPUT -j " + CHAIN + " 2>/dev/null; do :; done; " +
                "$IPT -t nat -A " + CHAIN + " -m owner --uid-owner " + appUid + " -j RETURN 2>/dev/null || true; " +
                "$IPT -t nat -A " + CHAIN + " -p udp --dport 53 -j REDIRECT --to-ports " + proxyPort + " || exit 22; " +
                "$IPT -t nat -A " + CHAIN + " -p tcp --dport 53 -j REDIRECT --to-ports " + proxyPort + " || exit 23; " +
                "$IPT -t nat -I OUTPUT 1 -j " + CHAIN + " || exit 24; " +
                "$IPT -t nat -L " + CHAIN + " -n >/dev/null || exit 25; " +
                "echo IPV4_OK; " +
                "if command -v ip6tables >/dev/null 2>&1; then " +
                "IP6=$(command -v ip6tables); " +
                "$IP6 -t nat -N " + CHAIN + " 2>/dev/null || true; " +
                "$IP6 -t nat -F " + CHAIN + " 2>/dev/null || true; " +
                "while $IP6 -t nat -D OUTPUT -j " + CHAIN + " 2>/dev/null; do :; done; " +
                "$IP6 -t nat -A " + CHAIN + " -m owner --uid-owner " + appUid + " -j RETURN 2>/dev/null || true; " +
                "$IP6 -t nat -A " + CHAIN + " -p udp --dport 53 -j REDIRECT --to-ports " + proxyPort + " 2>/dev/null && " +
                "$IP6 -t nat -A " + CHAIN + " -p tcp --dport 53 -j REDIRECT --to-ports " + proxyPort + " 2>/dev/null && " +
                "$IP6 -t nat -I OUTPUT 1 -j " + CHAIN + " 2>/dev/null && echo IPV6_OK || true; " +
                "fi";
        RootShell.Result result = RootShell.run(script, 15000);
        if (!result.ok()) disable();
        return result;
    }

    static RootShell.Result disable() {
        String script =
                "IPT=$(command -v iptables 2>/dev/null || echo iptables); " +
                "while $IPT -t nat -D OUTPUT -j " + CHAIN + " 2>/dev/null; do :; done; " +
                "$IPT -t nat -F " + CHAIN + " 2>/dev/null || true; " +
                "$IPT -t nat -X " + CHAIN + " 2>/dev/null || true; " +
                "if command -v ip6tables >/dev/null 2>&1; then " +
                "IP6=$(command -v ip6tables); " +
                "while $IP6 -t nat -D OUTPUT -j " + CHAIN + " 2>/dev/null; do :; done; " +
                "$IP6 -t nat -F " + CHAIN + " 2>/dev/null || true; " +
                "$IP6 -t nat -X " + CHAIN + " 2>/dev/null || true; " +
                "fi; echo CLEAN";
        return RootShell.run(script, 12000);
    }
}
