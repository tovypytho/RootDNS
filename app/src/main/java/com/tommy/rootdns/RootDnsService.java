package com.tommy.rootdns;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Automatic launcher for the strongest available DNS mode.
 * Root/netfilter interception is preferred when usable. If the virtual kernel has
 * no netfilter, a root netd/localhost resolver bridge is tried before VPN.
 */
public final class RootDnsService extends Service {
    static final String ACTION_ENABLE = "com.tommy.rootdns.ENABLE";
    static final String ACTION_DISABLE = "com.tommy.rootdns.DISABLE";
    static final String ACTION_STATUS = "com.tommy.rootdns.STATUS";
    static final String EXTRA_MESSAGE = "m";
    static final String EXTRA_NEED_VPN = "need_vpn";
    private static final String CHANNEL = "tdns";
    private static final int NOTIFICATION_ID = 4172;

    private final DnsProxyEngine engine = new DnsProxyEngine();
    private ScheduledExecutorService executor;
    private volatile boolean shuttingDown;
    private int failedHealthChecks;

    @Override public void onCreate() {
        super.onCreate();
        createChannel();
        startForeground(NOTIFICATION_ID, notification("Starting"));
        executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(new Runnable() {
            @Override public void run() { watchdog(); }
        }, 20, 20, TimeUnit.SECONDS);
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        final String action = intent == null ? null : intent.getAction();
        if (ACTION_DISABLE.equals(action)) {
            executor.execute(new Runnable() {
                @Override public void run() { disable(true, "Disabled"); }
            });
        } else if (ACTION_ENABLE.equals(action) || (action == null && AppPrefs.active(this))) {
            executor.execute(new Runnable() {
                @Override public void run() { enableAuto(); }
            });
        }
        return START_STICKY;
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }

    @Override public void onDestroy() {
        shuttingDown = true;
        // Root-mode failsafe only. Closing this service never tears down VpnDnsService.
        IptablesManager.disable();
        RootResolverManager.disable(this);
        engine.stop();
        if (executor != null) executor.shutdownNow();
        super.onDestroy();
    }

    private void enableAuto() {
        if (shuttingDown) return;
        publish("Checking integrity…", false, false);
        if (!IntegrityGuard.isTrusted(this)) {
            fail("Integrity check failed");
            return;
        }

        String endpoint;
        try {
            endpoint = DnsEndpointNormalizer.normalize(AppPrefs.endpoint(this));
        } catch (IllegalArgumentException e) {
            fail(e.getMessage());
            return;
        }

        // Remove stale interception state before deciding the mode.
        IptablesManager.disable();
        RootResolverManager.disable(this);
        engine.stop();

        publish("Checking root / netfilter…", false, false);
        if (!RootShell.hasRoot()) {
            fallbackToVpn("Root unavailable; using VPN DNS fallback.");
            return;
        }

        try {
            publish("Starting root DNS proxy…", false, false);
            engine.start(endpoint, BuildConfig.DNS_PROXY_PORT);
        } catch (Throwable e) {
            fallbackToVpn("Root proxy failed: " + safe(e.getMessage()));
            return;
        }

        publish("Testing DoH upstream…", false, false);
        if (!engine.healthCheck()) {
            engine.stop();
            // A failed upstream would also fail VPN mode, so do not obscure it as a netfilter issue.
            AppPrefs.diagnostics(this, "DoH health check failed before interception.\nEndpoint: " +
                    AppPrefs.endpoint(this));
            fail("DoH test failed");
            return;
        }

        publish("Trying root DNS interception…", false, false);
        RootShell.Result rules = IptablesManager.enable(getApplicationInfo().uid, BuildConfig.DNS_PROXY_PORT);
        if (rules.ok()) {
            AppPrefs.diagnostics(this, rules.output);
            failedHealthChecks = 0;
            AppPrefs.active(this, true);
            AppPrefs.mode(this, AppPrefs.MODE_ROOT);
            String mode = rules.output.indexOf("IPV6_OK") >= 0 ? "Root IPv4 + IPv6" : "Root IPv4";
            publish("Protected • " + mode, true, false);
            return;
        }

        String diagnostic = rules.output + "\n\nAUTO FALLBACK: netfilter unavailable; trying Android root resolver mode.";
        AppPrefs.diagnostics(this, diagnostic);
        publish("Trying root resolver fallback…", false, false);
        RootShell.Result resolver = RootResolverManager.enable(this, BuildConfig.DNS_PROXY_PORT);
        diagnostic += "\n\n" + resolver.output;
        AppPrefs.diagnostics(this, diagnostic);
        if (resolver.ok()) {
            failedHealthChecks = 0;
            AppPrefs.active(this, true);
            AppPrefs.mode(this, AppPrefs.MODE_ROOT_RESOLVER);
            publish("Protected • Root resolver + DoH", true, false);
            return;
        }

        engine.stop();
        fallbackToVpn("Root netfilter/resolver unavailable.");
    }

    private void fallbackToVpn(String reason) {
        IptablesManager.disable();
        RootResolverManager.disable(this);
        engine.stop();
        AppPrefs.active(this, false);
        AppPrefs.mode(this, AppPrefs.MODE_WAITING_VPN);

        Intent permission = VpnService.prepare(this);
        if (permission == null) {
            String before = AppPrefs.diagnostics(this);
            if (before == null || "Not run yet".equals(before)) before = "";
            String note = "AUTO MODE\n" + reason + "\nVPN permission=granted\nstarting DNS-only VPN";
            AppPrefs.diagnostics(this, before.length() == 0 ? note : before + "\n\n" + note);
            publish("Root resolver unavailable • switching to VPN DNS…", false, false);
            startVpnService();
            stopForeground(true);
            stopSelf();
        } else {
            String before = AppPrefs.diagnostics(this);
            if (before == null || "Not run yet".equals(before)) before = "";
            String note = "AUTO MODE\n" + reason + "\nVPN permission=required";
            AppPrefs.diagnostics(this, before.length() == 0 ? note : before + "\n\n" + note);
            publish("VPN permission required", false, true);
            stopForeground(true);
            stopSelf();
        }
    }

    private void startVpnService() {
        Intent vpn = new Intent(this, VpnDnsService.class);
        vpn.setAction(VpnDnsService.ACTION_START);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(vpn);
        else startService(vpn);
    }

    private void watchdog() {
        if (shuttingDown || !AppPrefs.active(this)) return;
        String mode = AppPrefs.mode(this);
        if (!AppPrefs.MODE_ROOT.equals(mode) && !AppPrefs.MODE_ROOT_RESOLVER.equals(mode)) return;

        boolean healthy = engine.isRunning() && engine.healthCheck();
        if (healthy && AppPrefs.MODE_ROOT_RESOLVER.equals(mode)) {
            healthy = RootResolverManager.ensure(this);
        }
        if (!healthy) {
            failedHealthChecks++;
            if (failedHealthChecks >= 3) {
                disable(false, "Failsafe: resolver/upstream unavailable; DNS restored");
            }
        } else {
            failedHealthChecks = 0;
        }
    }

    private void disable(boolean userRequested, String message) {
        IptablesManager.disable();
        RootResolverManager.disable(this);
        engine.stop();
        if (AppPrefs.MODE_ROOT.equals(AppPrefs.mode(this)) ||
                AppPrefs.MODE_ROOT_RESOLVER.equals(AppPrefs.mode(this)) ||
                AppPrefs.MODE_WAITING_VPN.equals(AppPrefs.mode(this))) {
            AppPrefs.active(this, false);
            AppPrefs.mode(this, AppPrefs.MODE_OFF);
        }
        publish(message, false, false);
        if (userRequested) {
            stopForeground(true);
            stopSelf();
        }
    }

    private void fail(String message) {
        IptablesManager.disable();
        RootResolverManager.disable(this);
        engine.stop();
        AppPrefs.active(this, false);
        AppPrefs.mode(this, AppPrefs.MODE_OFF);
        publish(message, false, false);
        stopForeground(true);
        stopSelf();
    }

    private void publish(String message, boolean active, boolean needVpn) {
        AppPrefs.status(this, message);
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIFICATION_ID, notification(message));
        Intent update = new Intent(ACTION_STATUS);
        update.setPackage(getPackageName());
        update.putExtra(EXTRA_MESSAGE, message);
        update.putExtra("active", active);
        update.putExtra(EXTRA_NEED_VPN, needVpn);
        update.putExtra("mode", AppPrefs.mode(this));
        sendBroadcast(update);
    }

    private Notification notification(String text) {
        Intent open = new Intent(this, MainActivity.class);
        int pFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) pFlags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, pFlags);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL)
                : new Notification.Builder(this);
        return b.setContentTitle("Tommy DNS")
                .setContentText(text)
                .setSmallIcon(com.tommy.rootdns.R.drawable.ic_launcher)
                .setOngoing(true)
                .setContentIntent(pi)
                .build();
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) {
                NotificationChannel c = new NotificationChannel(CHANNEL, "DNS protection",
                        NotificationManager.IMPORTANCE_LOW);
                c.setDescription("Keeps Tommy DNS automatic root/VPN mode alive");
                nm.createNotificationChannel(c);
            }
        }
    }

    private static String safe(String value) {
        return value == null || value.length() == 0 ? "unknown error" : value;
    }
}
