package com.tommy.rootdns;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;

public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        if (!AppPrefs.autoStart(context)) return;

        // If VPN consent was already granted and VPN was the last working mode, restore it directly.
        if (AppPrefs.MODE_VPN.equals(AppPrefs.mode(context)) && VpnService.prepare(context) == null) {
            Intent vpn = new Intent(context, VpnDnsService.class);
            vpn.setAction(VpnDnsService.ACTION_START);
            start(context, vpn);
            return;
        }

        // Otherwise let automatic mode test root/netfilter and fall back to VPN if permission exists.
        Intent service = new Intent(context, RootDnsService.class);
        service.setAction(RootDnsService.ACTION_ENABLE);
        start(context, service);
    }

    private static void start(Context context, Intent intent) {
        if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent);
        else context.startService(intent);
    }
}
