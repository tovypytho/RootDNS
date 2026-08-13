package com.tommy.rootdns;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int REQUEST_VPN = 901;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private TextView status;
    private TextView root;
    private TextView mode;
    private TextView diagnostics;
    private EditText endpoint;
    private Switch autoStart;
    private boolean receiverRegistered;
    private boolean vpnPromptOpen;

    private final BroadcastReceiver updates = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            String message = intent.getStringExtra(RootDnsService.EXTRA_MESSAGE);
            if (message != null) status.setText(message);
            refreshMode();
            if (diagnostics != null) diagnostics.setText(AppPrefs.diagnostics(MainActivity.this));
            if (intent.getBooleanExtra(RootDnsService.EXTRA_NEED_VPN, false)) {
                requestVpnPermission();
            }
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Window window = getWindow();
        window.setStatusBarColor(Color.BLACK);
        window.setNavigationBarColor(Color.BLACK);
        setContentView(buildUi());
        refresh();
        checkRoot();
    }

    @Override protected void onResume() {
        super.onResume();
        refresh();
        if (!receiverRegistered) {
            registerReceiver(updates, new IntentFilter(RootDnsService.ACTION_STATUS));
            receiverRegistered = true;
        }
        // If the app was left waiting for the system VPN consent dialog, recover cleanly.
        if (AppPrefs.MODE_WAITING_VPN.equals(AppPrefs.mode(this)) && VpnService.prepare(this) == null) {
            startVpnService();
        }
    }

    @Override protected void onPause() {
        if (receiverRegistered) {
            unregisterReceiver(updates);
            receiverRegistered = false;
        }
        super.onPause();
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_VPN) return;
        vpnPromptOpen = false;
        if (resultCode == RESULT_OK) {
            status.setText("VPN permission granted • starting…");
            startVpnService();
        } else {
            AppPrefs.active(this, false);
            AppPrefs.mode(this, AppPrefs.MODE_OFF);
            AppPrefs.status(this, "VPN permission denied");
            status.setText("VPN permission denied");
            refreshMode();
        }
    }

    private View buildUi() {
        int pad = dp(22);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Color.rgb(11, 13, 16));

        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(pad, dp(26), pad, dp(34));
        scroll.addView(body, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView wm = text("Tommy", 13, Color.rgb(147, 155, 168));
        wm.setGravity(Gravity.CENTER_HORIZONTAL);
        wm.setLetterSpacing(0.18f);
        body.addView(wm, lp(-1, -2, 0, 0, 0, 10));

        TextView title = text("Root DNS", 30, Color.rgb(244, 246, 248));
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        body.addView(title, lp(-1, -2, 0, 0, 0, 6));

        TextView sub = text("Automatic root DNS → VPN DNS fallback for Android 7+", 13,
                Color.rgb(147, 155, 168));
        sub.setGravity(Gravity.CENTER_HORIZONTAL);
        body.addView(sub, lp(-1, -2, 0, 0, 0, 24));

        LinearLayout card = card();
        body.addView(card, lp(-1, -2, 0, 0, 0, 16));

        card.addView(label("STATUS"));
        status = text("Idle", 18, Color.WHITE);
        status.setTextIsSelectable(true);
        card.addView(status, lp(-1, -2, 0, 5, 0, 18));

        card.addView(label("MODE"));
        mode = text("Automatic", 15, Color.rgb(233, 237, 242));
        card.addView(mode, lp(-1, -2, 0, 5, 0, 18));

        card.addView(label("ROOT"));
        root = text("Checking…", 15, Color.rgb(233, 237, 242));
        card.addView(root, lp(-1, -2, 0, 5, 0, 0));

        TextView dnsLabel = label("DNS / DOH ENDPOINT");
        body.addView(dnsLabel, lp(-1, -2, 0, 4, 0, 8));

        endpoint = new EditText(this);
        endpoint.setSingleLine(true);
        endpoint.setTextSize(15);
        endpoint.setTextColor(Color.rgb(244, 246, 248));
        endpoint.setHintTextColor(Color.rgb(100, 107, 118));
        endpoint.setHint("49aa48.dns.nextdns.io");
        endpoint.setPadding(dp(14), 0, dp(14), 0);
        endpoint.setBackground(round(Color.rgb(20, 23, 28), dp(12)));
        body.addView(endpoint, lp(-1, dp(52), 0, 0, 0, 9));

        TextView hint = text("Accepts a NextDNS hostname/profile ID or any HTTPS DoH URL.", 12,
                Color.rgb(147, 155, 168));
        body.addView(hint, lp(-1, -2, 0, 0, 0, 18));

        autoStart = new Switch(this);
        autoStart.setText("Start on boot");
        autoStart.setTextSize(15);
        autoStart.setTextColor(Color.rgb(244, 246, 248));
        autoStart.setPadding(0, dp(4), 0, dp(4));
        autoStart.setOnCheckedChangeListener((buttonView, isChecked) -> AppPrefs.autoStart(this, isChecked));
        body.addView(autoStart, lp(-1, -2, 0, 0, 0, 18));

        Button enable = button("ENABLE DNS", true);
        enable.setOnClickListener(v -> enableDns());
        body.addView(enable, lp(-1, dp(54), 0, 0, 0, 10));

        Button disable = button("DISABLE", false);
        disable.setOnClickListener(v -> disableDns());
        body.addView(disable, lp(-1, dp(50), 0, 0, 0, 10));

        Button check = button("CHECK ROOT", false);
        check.setOnClickListener(v -> checkRoot());
        body.addView(check, lp(-1, dp(50), 0, 0, 0, 10));

        Button runDiag = button("RUN DIAGNOSTICS", false);
        runDiag.setOnClickListener(v -> runDiagnostics());
        body.addView(runDiag, lp(-1, dp(50), 0, 0, 0, 16));

        LinearLayout diagCard = card();
        body.addView(diagCard, lp(-1, -2, 0, 0, 0, 10));
        diagCard.addView(label("DIAGNOSTICS"));
        diagnostics = text("Not run yet", 10, Color.rgb(192, 199, 209));
        diagnostics.setTypeface(Typeface.MONOSPACE);
        diagnostics.setTextIsSelectable(true);
        diagCard.addView(diagnostics, lp(-1, -2, 0, 8, 0, 8));

        Button copy = button("COPY DIAGNOSTICS", false);
        copy.setOnClickListener(v -> copyDiagnostics());
        body.addView(copy, lp(-1, dp(48), 0, 0, 0, 18));

        TextView note = text("v1.2 automatically tries root/iptables first. If VPhoneGaGa exposes no netfilter tables, Tommy switches to a DNS-only Android VPN and sends standard system DNS through DoH. Apps that use their own DoH/DoT or direct hard-coded DNS sockets can still bypass DNS-only VPN mode.", 12,
                Color.rgb(120, 128, 140));
        body.addView(note);

        return scroll;
    }

    private void enableDns() {
        String value = endpoint.getText().toString().trim();
        try {
            DnsEndpointNormalizer.normalize(value);
        } catch (IllegalArgumentException e) {
            status.setText(e.getMessage());
            return;
        }
        AppPrefs.endpoint(this, value.length() == 0 ? DnsEndpointNormalizer.defaultDisplayValue() : value);
        AppPrefs.diagnostics(this, "Starting automatic root/VPN enable attempt…");
        diagnostics.setText(AppPrefs.diagnostics(this));
        status.setText("Starting automatic mode…");
        Intent intent = new Intent(this, RootDnsService.class);
        intent.setAction(RootDnsService.ACTION_ENABLE);
        startCompatService(intent);
    }

    private void disableDns() {
        status.setText("Disabling…");
        Intent rootIntent = new Intent(this, RootDnsService.class);
        rootIntent.setAction(RootDnsService.ACTION_DISABLE);
        startCompatService(rootIntent);

        Intent vpnIntent = new Intent(this, VpnDnsService.class);
        vpnIntent.setAction(VpnDnsService.ACTION_STOP);
        startCompatService(vpnIntent);
    }

    private void requestVpnPermission() {
        if (vpnPromptOpen) return;
        Intent prepare = VpnService.prepare(this);
        if (prepare == null) {
            startVpnService();
            return;
        }
        vpnPromptOpen = true;
        try {
            startActivityForResult(prepare, REQUEST_VPN);
        } catch (Throwable e) {
            vpnPromptOpen = false;
            status.setText("Could not open VPN permission: " + safe(e.getMessage()));
        }
    }

    private void startVpnService() {
        AppPrefs.mode(this, AppPrefs.MODE_WAITING_VPN);
        Intent vpn = new Intent(this, VpnDnsService.class);
        vpn.setAction(VpnDnsService.ACTION_START);
        startCompatService(vpn);
    }

    private void startCompatService(Intent intent) {
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent);
        else startService(intent);
    }

    private void checkRoot() {
        root.setText("Checking…");
        worker.execute(new Runnable() {
            @Override public void run() {
                final RootShell.Result result = RootShell.run("id", 8000);
                final boolean ok = result.ok() && result.output.indexOf("uid=0") >= 0;
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        root.setText(ok ? "Granted ✓" : "Not granted • VPN mode still works");
                        if (!ok && result.output.length() > 0) {
                            AppPrefs.diagnostics(MainActivity.this,
                                    "Root check code=" + result.code + "\n" + result.output);
                            diagnostics.setText(AppPrefs.diagnostics(MainActivity.this));
                        }
                    }
                });
            }
        });
    }

    private void runDiagnostics() {
        diagnostics.setText("Running root/netfilter/VPN diagnostics…");
        status.setText("Diagnosing…");
        worker.execute(new Runnable() {
            @Override public void run() {
                final String result = NetworkDiagnostics.run(MainActivity.this);
                AppPrefs.diagnostics(MainActivity.this, result);
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        diagnostics.setText(result);
                        status.setText("Diagnostics complete");
                    }
                });
            }
        });
    }

    private void copyDiagnostics() {
        String value = diagnostics == null ? AppPrefs.diagnostics(this) : diagnostics.getText().toString();
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText("TommyRootDNS diagnostics", value));
            Toast.makeText(this, "Diagnostics copied", Toast.LENGTH_SHORT).show();
        }
    }

    private void refresh() {
        if (status != null) status.setText(AppPrefs.status(this));
        if (endpoint != null) endpoint.setText(AppPrefs.endpoint(this));
        if (autoStart != null) autoStart.setChecked(AppPrefs.autoStart(this));
        if (diagnostics != null) diagnostics.setText(AppPrefs.diagnostics(this));
        refreshMode();
    }

    private void refreshMode() {
        if (mode == null) return;
        String value = AppPrefs.mode(this);
        if (AppPrefs.MODE_ROOT.equals(value)) mode.setText("Root / iptables");
        else if (AppPrefs.MODE_VPN.equals(value)) mode.setText("VPN DNS fallback");
        else if (AppPrefs.MODE_WAITING_VPN.equals(value)) mode.setText("Automatic • waiting for VPN");
        else mode.setText("Automatic");
    }

    private LinearLayout card() {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        view.setPadding(dp(16), dp(16), dp(16), dp(16));
        view.setBackground(round(Color.rgb(20, 23, 28), dp(14)));
        return view;
    }

    private TextView label(String value) {
        TextView v = text(value, 11, Color.rgb(147, 155, 168));
        v.setLetterSpacing(0.14f);
        return v;
    }

    private Button button(String value, boolean primary) {
        Button b = new Button(this);
        b.setText(value);
        b.setTextSize(14);
        b.setAllCaps(false);
        b.setTextColor(primary ? Color.rgb(16, 18, 21) : Color.rgb(239, 242, 246));
        b.setBackground(round(primary ? Color.rgb(230, 235, 242) : Color.rgb(20, 23, 28), dp(12)));
        return b;
    }

    private TextView text(String value, int sp, int color) {
        TextView v = new TextView(this);
        v.setText(value);
        v.setTextSize(sp);
        v.setTextColor(color);
        return v;
    }

    private LinearLayout.LayoutParams lp(int width, int height, int l, int t, int r, int b) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(width, height);
        p.setMargins(dp(l), dp(t), dp(r), dp(b));
        return p;
    }

    private GradientDrawable round(int color, int radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(radius);
        return d;
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private static String safe(String value) {
        return value == null || value.length() == 0 ? "unknown error" : value;
    }
}
