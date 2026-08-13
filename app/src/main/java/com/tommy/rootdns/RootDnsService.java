package com.tommy.rootdns;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class RootDnsService extends Service {
    static final String ACTION_ENABLE = "com.tommy.rootdns.ENABLE";
    static final String ACTION_DISABLE = "com.tommy.rootdns.DISABLE";
    static final String ACTION_STATUS = "com.tommy.rootdns.STATUS";
    static final String EXTRA_MESSAGE = "m";
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
                @Override public void run() { enable(); }
            });
        }
        return START_STICKY;
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }

    @Override public void onDestroy() {
        shuttingDown = true;
        // Failsafe: never intentionally leave redirect rules pointing at a dead userspace proxy.
        IptablesManager.disable();
        engine.stop();
        if (executor != null) executor.shutdownNow();
        super.onDestroy();
    }

    private void enable() {
        if (shuttingDown) return;
        publish("Checking integrity…", false);
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

        publish("Requesting root…", false);
        if (!RootShell.hasRoot()) {
            AppPrefs.diagnostics(this, "Root check failed: su did not return uid=0");
            fail("Root permission not granted");
            return;
        }

        // Clean stale rules first. With no redirect, failed startup simply falls back to system DNS.
        IptablesManager.disable();
        engine.stop();

        try {
            publish("Starting local DNS proxy…", false);
            engine.start(endpoint, BuildConfig.DNS_PROXY_PORT);
        } catch (Throwable e) {
            fail("Proxy start failed: " + safe(e.getMessage()));
            return;
        }

        publish("Testing DoH upstream…", false);
        if (!engine.healthCheck()) {
            engine.stop();
            AppPrefs.diagnostics(this, "DoH health check failed before iptables interception.\nEndpoint: " + AppPrefs.endpoint(this));
            fail("DoH test failed; interception was not enabled");
            return;
        }

        int uid = getApplicationInfo().uid;
        publish("Configuring DNS interception…", false);
        RootShell.Result rules = IptablesManager.enable(uid, BuildConfig.DNS_PROXY_PORT);
        if (!rules.ok()) {
            AppPrefs.diagnostics(this, rules.output);
            engine.stop();
            fail("iptables: " + IptablesManager.failureSummary(rules) + " • see diagnostics");
            return;
        }

        AppPrefs.diagnostics(this, rules.output);
        failedHealthChecks = 0;
        AppPrefs.active(this, true);
        String mode = rules.output.indexOf("IPV6_OK") >= 0 ? "IPv4 + IPv6" : "IPv4";
        publish("Protected • " + mode, true);
    }

    private void watchdog() {
        if (shuttingDown || !AppPrefs.active(this)) return;
        if (!engine.isRunning() || !engine.healthCheck()) {
            failedHealthChecks++;
            if (failedHealthChecks >= 3) {
                // Restore normal DNS rather than black-holing all port-53 traffic.
                disable(false, "Failsafe: upstream unavailable; DNS restored");
            }
        } else {
            failedHealthChecks = 0;
        }
    }

    private void disable(boolean userRequested, String message) {
        IptablesManager.disable();
        engine.stop();
        AppPrefs.active(this, false);
        publish(message, false);
        if (userRequested) stopSelf();
    }

    private void fail(String message) {
        IptablesManager.disable();
        engine.stop();
        AppPrefs.active(this, false);
        publish(message, false);
    }

    private void publish(String message, boolean active) {
        AppPrefs.status(this, message);
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIFICATION_ID, notification(message));
        Intent update = new Intent(ACTION_STATUS);
        update.setPackage(getPackageName());
        update.putExtra(EXTRA_MESSAGE, message);
        update.putExtra("active", active);
        sendBroadcast(update);
    }

    private Notification notification(String text) {
        Intent open = new Intent(this, MainActivity.class);
        int pFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) pFlags |= PendingIntent.FLAG_IMMUTABLE;
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, pFlags);
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= 26) {
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
        }
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
                c.setDescription("Keeps the local DNS proxy alive");
                nm.createNotificationChannel(c);
            }
        }
    }

    private static String safe(String value) {
        return value == null ? "unknown error" : value;
    }
}
