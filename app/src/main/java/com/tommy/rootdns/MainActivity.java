package com.tommy.rootdns;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private TextView status;
    private TextView root;
    private EditText endpoint;
    private Switch autoStart;
    private boolean receiverRegistered;

    private final BroadcastReceiver updates = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            String message = intent.getStringExtra(RootDnsService.EXTRA_MESSAGE);
            if (message != null) status.setText(message);
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

        TextView sub = text("System-wide DNS53 → DNS-over-HTTPS for rooted Android 7+", 13,
                Color.rgb(147, 155, 168));
        sub.setGravity(Gravity.CENTER_HORIZONTAL);
        body.addView(sub, lp(-1, -2, 0, 0, 0, 24));

        LinearLayout card = card();
        body.addView(card, lp(-1, -2, 0, 0, 0, 16));

        card.addView(label("STATUS"));
        status = text("Idle", 18, Color.WHITE);
        card.addView(status, lp(-1, -2, 0, 5, 0, 18));
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
        body.addView(check, lp(-1, dp(50), 0, 0, 0, 18));

        TextView note = text("Port 53 traffic is redirected with a dedicated iptables chain. Apps that use their own DoH/DoT, VPN, or hard-coded IPs can bypass standard DNS interception.", 12,
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
        status.setText("Starting…");
        Intent intent = new Intent(this, RootDnsService.class);
        intent.setAction(RootDnsService.ACTION_ENABLE);
        startService(intent);
    }

    private void disableDns() {
        status.setText("Disabling…");
        Intent intent = new Intent(this, RootDnsService.class);
        intent.setAction(RootDnsService.ACTION_DISABLE);
        startService(intent);
    }

    private void checkRoot() {
        root.setText("Checking…");
        worker.execute(new Runnable() {
            @Override public void run() {
                final boolean ok = RootShell.hasRoot();
                runOnUiThread(new Runnable() {
                    @Override public void run() { root.setText(ok ? "Granted ✓" : "Not granted"); }
                });
            }
        });
    }

    private void refresh() {
        if (status != null) status.setText(AppPrefs.status(this));
        if (endpoint != null) endpoint.setText(AppPrefs.endpoint(this));
        if (autoStart != null) autoStart.setChecked(AppPrefs.autoStart(this));
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
        v.setLetterSpacing(0.12f);
        return v;
    }

    private Button button(String value, boolean primary) {
        Button b = new Button(this);
        b.setText(value);
        b.setTextSize(13);
        b.setAllCaps(false);
        b.setTextColor(primary ? Color.rgb(15, 17, 20) : Color.rgb(244, 246, 248));
        b.setBackground(round(primary ? Color.rgb(233, 237, 242) : Color.rgb(20, 23, 28), dp(12)));
        return b;
    }

    private TextView text(String value, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(sp);
        t.setTextColor(color);
        t.setLineSpacing(0, 1.08f);
        return t;
    }

    private GradientDrawable round(int color, float radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(radius);
        return d;
    }

    private LinearLayout.LayoutParams lp(int w, int h, int l, int t, int r, int b) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h);
        p.setMargins(dp(l), dp(t), dp(r), dp(b));
        return p;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
