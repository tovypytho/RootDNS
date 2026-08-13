package com.tommy.rootdns;

import android.content.Context;
import android.content.SharedPreferences;

final class AppPrefs {
    private static final String FILE = "t";
    private static final String K_ENDPOINT = "e";
    private static final String K_AUTO = "a";
    private static final String K_ACTIVE = "x";
    private static final String K_STATUS = "s";

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
}
