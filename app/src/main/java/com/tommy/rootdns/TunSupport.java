package com.tommy.rootdns;

/** Root-assisted diagnostics/repair for legacy Android VPN TUN device exposure. */
final class TunSupport {
    private TunSupport() {}

    static String diagnostics() {
        StringBuilder out = new StringBuilder();
        out.append("=== TUN DEVICE ===\n");
        append(out, "/dev/tun", RootShell.run("ls -lZ /dev/tun 2>&1 || ls -l /dev/tun 2>&1 || true", 7000));
        append(out, "char device", RootShell.run("if [ -c /dev/tun ]; then echo yes; else echo no; fi", 7000));
        append(out, "/proc/misc tun", RootShell.run("grep -i '[[:space:]]tun$' /proc/misc 2>/dev/null || true", 7000));
        append(out, "kernel config", RootShell.run("(zcat /proc/config.gz 2>/dev/null || cat /proc/config.gz 2>/dev/null || true) | grep -E '^CONFIG_TUN=' || true", 7000));
        append(out, "proc net dev", RootShell.run("cat /proc/net/dev 2>/dev/null | head -n 40 || true", 7000));
        return out.toString();
    }

    /**
     * Some virtual Android builds have CONFIG_TUN but omit /dev/tun. In that narrow case,
     * create the standard 10:200 device node and apply the Android tun_device label if possible.
     * If the kernel does not register TUN, this intentionally does nothing.
     */
    static String repairIfSafe() {
        RootShell.Result state = RootShell.run(
                "if [ -c /dev/tun ]; then echo present; " +
                "elif grep -qi '[[:space:]]tun$' /proc/misc 2>/dev/null; then echo kernel-present-node-missing; " +
                "else echo kernel-tun-not-detected; fi", 7000);
        String value = state.output == null ? "" : state.output.trim();
        if (!value.contains("kernel-present-node-missing")) {
            return "TUN repair: " + (value.length() == 0 ? "unknown" : value);
        }

        RootShell.Result repair = RootShell.run(
                "rm -f /dev/tun 2>/dev/null; " +
                "mknod /dev/tun c 10 200 2>&1; " +
                "chmod 0666 /dev/tun 2>&1; " +
                "(chcon u:object_r:tun_device:s0 /dev/tun 2>/dev/null || restorecon /dev/tun 2>/dev/null || true); " +
                "ls -lZ /dev/tun 2>&1 || ls -l /dev/tun 2>&1", 10000);
        return "TUN repair attempted: code=" + repair.code + " • " + compact(repair.output);
    }

    private static void append(StringBuilder out, String label, RootShell.Result result) {
        out.append(label).append(": code=").append(result.code).append(" • ");
        out.append(compact(result.output)).append('\n');
    }

    private static String compact(String s) {
        if (s == null) return "";
        s = s.trim().replace('\n', ' ').replace('\r', ' ');
        while (s.contains("  ")) s = s.replace("  ", " ");
        return s.length() == 0 ? "(no output)" : s;
    }
}
