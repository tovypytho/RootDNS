package com.tommy.rootdns;

import android.content.Context;
import android.content.SharedPreferences;

final class AppPrefs {
    static final String MODE_OFF = "OFF";
    static final String MODE_ROOT = "ROOT";
    static final String MODE_VPN = "VPN";
    static final String MODE_ROOT_RESOLVER = "ROOT_RESOLVER";
    static final String MODE_WAITING_VPN = "WAITING_VPN";

    private static final String FILE = "t";
    private static final String K_ENDPOINT = "e";
    private static final String K_AUTO = "a";
    private static final String K_ACTIVE = "x";
    private static final String K_STATUS = "s";
    private static final String K_DIAG = "d";
    private static final String K_MODE = "m";
    private static final String K_R_NET = "rn";
    private static final String K_R_DNS = "rd";
    private static final String K_R_DOM = "ro";
    private static final String K_R_P1 = "r1";
    private static final String K_R_P2 = "r2";

    private AppPrefs() {}

    private static SharedPreferences p(Context context) {
        return context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    static String endpoint(Context context) {
        return p(context).getString(K_ENDPOINT, DnsEndpointNormalizer.defaultDisplayValue());
    }

    static void endpoint(Context context, String value) {
        p(context).edit().putString(K_ENDPOINT, value).apply();
    }

    static boolean autoStart(Context context) {
        return p(context).getBoolean(K_AUTO, false);
    }

    static void autoStart(Context context, boolean value) {
        p(context).edit().putBoolean(K_AUTO, value).apply();
    }

    static boolean active(Context context) {
        return p(context).getBoolean(K_ACTIVE, false);
    }

    static void active(Context context, boolean value) {
        p(context).edit().putBoolean(K_ACTIVE, value).apply();
    }

    static String status(Context context) {
        return p(context).getString(K_STATUS, "Idle");
    }

    static void status(Context context, String value) {
        p(context).edit().putString(K_STATUS, value).apply();
    }

    static String diagnostics(Context context) {
        return p(context).getString(K_DIAG, "Not run yet");
    }

    static void diagnostics(Context context, String value) {
        p(context).edit().putString(K_DIAG, value == null ? "" : value).apply();
    }

    static String mode(Context context) {
        return p(context).getString(K_MODE, MODE_OFF);
    }

    static void mode(Context context, String value) {
        p(context).edit().putString(K_MODE, value == null ? MODE_OFF : value).apply();
    }

    static void resolverBackup(Context context, int netId, String dns, String domains, String prop1, String prop2) {
        p(context).edit()
                .putInt(K_R_NET, netId)
                .putString(K_R_DNS, dns == null ? "" : dns)
                .putString(K_R_DOM, domains == null ? "" : domains)
                .putString(K_R_P1, prop1 == null ? "" : prop1)
                .putString(K_R_P2, prop2 == null ? "" : prop2)
                .apply();
    }

    static int resolverNetId(Context context) { return p(context).getInt(K_R_NET, -1); }
    static String resolverDns(Context context) { return p(context).getString(K_R_DNS, ""); }
    static String resolverDomains(Context context) { return p(context).getString(K_R_DOM, ""); }
    static String resolverProp1(Context context) { return p(context).getString(K_R_P1, ""); }
    static String resolverProp2(Context context) { return p(context).getString(K_R_P2, ""); }

    static void clearResolverBackup(Context context) {
        p(context).edit()
                .remove(K_R_NET).remove(K_R_DNS).remove(K_R_DOM).remove(K_R_P1).remove(K_R_P2)
                .apply();
    }
}

