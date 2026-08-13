package com.tommy.rootdns;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DNS-only VPN fallback for devices whose kernels expose no usable iptables/netfilter NAT.
 * Only the synthetic DNS server 10.77.0.2/32 is routed into the TUN. Other traffic stays on
 * the normal Android network, so this service does not need a full TCP/IP forwarding stack.
 */
public final class VpnDnsService extends VpnService {
    static final String ACTION_START = "com.tommy.rootdns.VPN_START";
    static final String ACTION_STOP = "com.tommy.rootdns.VPN_STOP";

    private static final String CHANNEL = "tdns_vpn";
    private static final int NOTIFICATION_ID = 4173;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService queryWorkers = Executors.newFixedThreadPool(4);
    private final Object writeLock = new Object();
    private volatile boolean running;
    private volatile boolean stopping;
    private ParcelFileDescriptor tun;
    private FileInputStream input;
    private FileOutputStream output;
    private DohClient doh;
    private final AtomicLong queries = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();

    @Override public void onCreate() {
        super.onCreate();
        createChannel();
        startForeground(NOTIFICATION_ID, notification("VPN DNS starting"));
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            // Do not queue STOP behind packetLoop(): closing the TUN here unblocks its read.
            shutdown("Disabled", true);
        } else {
            worker.execute(new Runnable() {
                @Override public void run() { startVpn(); }
            });
        }
        return START_STICKY;
    }

    @Override public void onRevoke() {
        shutdown("VPN permission revoked", true);
        super.onRevoke();
    }

    @Override public void onDestroy() {
        stopping = true;
        closeTun();
        worker.shutdownNow();
        queryWorkers.shutdownNow();
        if (AppPrefs.MODE_VPN.equals(AppPrefs.mode(this))) {
            AppPrefs.active(this, false);
            AppPrefs.mode(this, AppPrefs.MODE_OFF);
        }
        super.onDestroy();
    }

    private void startVpn() {
        if (running || stopping) return;
        if (!IntegrityGuard.isTrusted(this)) {
            fail("Integrity check failed");
            return;
        }
        if (VpnService.prepare(this) != null) {
            AppPrefs.mode(this, AppPrefs.MODE_WAITING_VPN);
            fail("VPN permission required; open Tommy DNS");
            return;
        }

        String endpoint;
        try {
            endpoint = DnsEndpointNormalizer.normalize(AppPrefs.endpoint(this));
        } catch (IllegalArgumentException e) {
            fail(e.getMessage());
            return;
        }

        publish("Testing DoH for VPN mode…", false);
        try {
            // Bootstrap the upstream before the VPN interface is established.
            doh = new DohClient(endpoint);
            byte[] test = doh.query(DnsPackets.aQuery("example.com"));
            if (test == null || test.length < 12 || (test[2] & 0x80) == 0) {
                throw new IOException("Invalid DoH test response");
            }
        } catch (Throwable e) {
            fail("DoH test failed: " + safe(e.getMessage()));
            return;
        }

        try {
            String repair = TunSupport.repairIfSafe();
            appendDiagnostics(repair);

            EstablishResult established = establishCompatibleTun();
            tun = established.tun;
            if (tun == null) throw new IOException("VPN establish returned null");
            input = new FileInputStream(tun.getFileDescriptor());
            output = new FileOutputStream(tun.getFileDescriptor());
            running = true;
            queries.set(0);
            failures.set(0);
            AppPrefs.active(this, true);
            AppPrefs.mode(this, AppPrefs.MODE_VPN);
            appendDiagnostics("VPN mode established\n" +
                    "profile=" + established.profile + "\n" +
                    "tun=" + VpnDnsPacket.TUN_IP_TEXT + "/" + established.prefix + "\n" +
                    "dns=" + VpnDnsPacket.DNS_IP_TEXT + "/32\n" +
                    "route=DNS-only\n" +
                    "endpoint=" + AppPrefs.endpoint(this));
            publish("Protected • VPN DNS", true);
            packetLoop();
        } catch (Throwable e) {
            appendDiagnostics("VPN establish final failure: " + e.getClass().getSimpleName() + ": " + safe(e.getMessage()) + "\n" + TunSupport.diagnostics());
            fail("VPN start failed: " + safe(e.getMessage()) + " • see diagnostics");
        }
    }

    private EstablishResult establishCompatibleTun() throws IOException {
        Throwable last = null;

        // Android 7's native VPN code throws the generic "Cannot create interface" for
        // failures opening/allocating/activating TUN *and* for SIOCSIFMTU failures. v1.2
        // forced MTU 32767; the compatibility path first leaves MTU unset so Android/kernel picks its default.
        final int[] prefixes = new int[] { 32, 24, 24 };
        final int[] mtus = new int[] { 0, 0, 1500 };
        final String[] names = new String[] {
                "legacy-default-mtu-/32",
                "legacy-default-mtu-/24",
                "legacy-mtu1500-/24"
        };

        for (int i = 0; i < names.length; i++) {
            try {
                Builder builder = new Builder()
                        .setSession("Tommy DNS")
                        .addAddress(VpnDnsPacket.TUN_IP_TEXT, prefixes[i])
                        .addRoute(VpnDnsPacket.DNS_IP_TEXT, 32)
                        .addDnsServer(VpnDnsPacket.DNS_IP_TEXT)
                        .setBlocking(true);
                if (mtus[i] > 0) builder.setMtu(mtus[i]);

                ParcelFileDescriptor pfd = builder.establish();
                if (pfd != null) {
                    appendDiagnostics("VPN establish success: " + names[i]);
                    return new EstablishResult(pfd, names[i], prefixes[i]);
                }
                appendDiagnostics("VPN establish returned null: " + names[i]);
            } catch (Throwable e) {
                last = e;
                appendDiagnostics("VPN establish failed [" + names[i] + "]: " +
                        e.getClass().getSimpleName() + ": " + safe(e.getMessage()));
            }
        }

        if (last instanceof IOException) throw (IOException) last;
        if (last != null) throw new IOException(last.getClass().getSimpleName() + ": " + safe(last.getMessage()), last);
        throw new IOException("Cannot establish VPN interface");
    }

    private static final class EstablishResult {
        final ParcelFileDescriptor tun;
        final String profile;
        final int prefix;

        EstablishResult(ParcelFileDescriptor tun, String profile, int prefix) {
            this.tun = tun;
            this.profile = profile;
            this.prefix = prefix;
        }
    }

    private void packetLoop() {
        byte[] packet = new byte[65535];
        while (running && !stopping) {
            int length;
            try {
                length = input.read(packet);
            } catch (IOException e) {
                if (running && !stopping) fail("VPN read failed: " + safe(e.getMessage()));
                return;
            }
            if (length <= 0) continue;

            VpnDnsPacket.Query query = VpnDnsPacket.parseUdpDnsQuery(packet, length);
            if (query == null) continue;

            final VpnDnsPacket.Query captured = query;
            final long count = queries.incrementAndGet();
            queryWorkers.execute(new Runnable() {
                @Override public void run() { handleQuery(captured); }
            });

            if (count == 1 || count % 50 == 0) {
                publish("Protected • VPN DNS • q=" + count, true);
            }
        }
    }

    private void handleQuery(VpnDnsPacket.Query query) {
        if (!running || stopping) return;
        byte[] response;
        try {
            response = doh.query(query.dnsMessage);
            if (response == null || response.length < 12) throw new IOException("Short DoH response");
        } catch (Throwable e) {
            long failed = failures.incrementAndGet();
            response = VpnDnsPacket.servFail(query.dnsMessage);
            if (failed <= 3 || failed % 10 == 0) {
                appendDiagnostics("VPN DoH query failure #" + failed + ": " + safe(e.getMessage()));
            }
        }

        try {
            byte[] reply = VpnDnsPacket.buildUdpResponse(query, response);
            synchronized (writeLock) {
                if (!running || stopping || output == null) return;
                output.write(reply);
                output.flush();
            }
        } catch (Throwable e) {
            failures.incrementAndGet();
            appendDiagnostics("VPN packet write failure: " + safe(e.getMessage()));
        }
    }

    private void shutdown(String message, boolean stop) {
        running = false;
        closeTun();
        AppPrefs.active(this, false);
        AppPrefs.mode(this, AppPrefs.MODE_OFF);
        publish(message, false);
        if (stop) {
            stopForeground(true);
            stopSelf();
        }
    }

    private void fail(String message) {
        running = false;
        closeTun();
        AppPrefs.active(this, false);
        if (!AppPrefs.MODE_WAITING_VPN.equals(AppPrefs.mode(this))) {
            AppPrefs.mode(this, AppPrefs.MODE_OFF);
        }
        publish(message, false);
        stopForeground(true);
        stopSelf();
    }

    private void closeTun() {
        running = false;
        if (input != null) {
            try { input.close(); } catch (IOException ignored) {}
            input = null;
        }
        if (output != null) {
            try { output.close(); } catch (IOException ignored) {}
            output = null;
        }
        if (tun != null) {
            try { tun.close(); } catch (IOException ignored) {}
            tun = null;
        }
    }

    private void appendDiagnostics(String text) {
        String before = AppPrefs.diagnostics(this);
        if (before == null || "Not run yet".equals(before)) before = "";
        String combined = before.length() == 0 ? text : before + "\n\n" + text;
        if (combined.length() > 24000) combined = combined.substring(combined.length() - 24000);
        AppPrefs.diagnostics(this, combined);
    }

    private void publish(String message, boolean active) {
        AppPrefs.status(this, message);
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(NOTIFICATION_ID, notification(message));
        Intent update = new Intent(RootDnsService.ACTION_STATUS);
        update.setPackage(getPackageName());
        update.putExtra(RootDnsService.EXTRA_MESSAGE, message);
        update.putExtra("active", active);
        update.putExtra("mode", AppPrefs.MODE_VPN);
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
                NotificationChannel c = new NotificationChannel(CHANNEL, "VPN DNS protection",
                        NotificationManager.IMPORTANCE_LOW);
                c.setDescription("DNS-only VPN fallback for Tommy DNS");
                nm.createNotificationChannel(c);
            }
        }
    }

    private static String safe(String value) {
        return value == null || value.length() == 0 ? "unknown error" : value;
    }
}
