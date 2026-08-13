package com.tommy.rootdns;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        if (!AppPrefs.autoStart(context)) return;
        AppPrefs.active(context, true);
        Intent service = new Intent(context, RootDnsService.class);
        service.setAction(RootDnsService.ACTION_ENABLE);
        if (Build.VERSION.SDK_INT >= 26) {
            context.startForegroundService(service);
        } else {
            context.startService(service);
        }
    }
}
