package com.tommy.rootdns;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Root command transport.
 *
 * v1.6 keeps one interactive root shell alive for the lifetime of the app process.
 * Older builds spawned `su -c ...` for every probe/watchdog command; many root
 * managers show a "Superuser granted" toast for every su request, which caused
 * continuous toast spam. Commands are now multiplexed through one `su -c sh`
 * session, so a normal app session should cause only one root-manager grant toast.
 */
final class RootShell {
    static final class Result {
        final int code;
        final String output;
        Result(int code, String output) {
            this.code = code;
            this.output = output == null ? "" : output;
        }
        boolean ok() { return code == 0; }
    }

    private static final int MAX_CAPTURE = 64 * 1024;
    private static final Object LOCK = new Object();
    private static final AtomicLong COMMAND_ID = new AtomicLong(1);

    private static Process session;
    private static BufferedWriter sessionInput;
    private static BlockingQueue<String> sessionOutput;
    private static Thread sessionDrain;
    private static String sessionMode = "not-open";
    private static boolean cachedRoot;

    private RootShell() {}

    static boolean hasRoot() {
        synchronized (LOCK) {
            if (cachedRoot && sessionAliveLocked()) return true;
        }
        Result result = run("id", 12000);
        return result.ok() && result.output.indexOf("uid=0") >= 0;
    }

    static String sessionMode() {
        synchronized (LOCK) {
            if (sessionAliveLocked()) return sessionMode;
            return "not-open";
        }
    }

    static Result run(String command) {
        return run(command, 12000);
    }

    static Result run(String command, long timeoutMs) {
        synchronized (LOCK) {
            if (ensureSessionLocked()) {
                return executePersistentLocked(command, timeoutMs);
            }
            // Compatibility fallback for unusual su implementations that cannot keep
            // an interactive shell alive. This may still produce one toast per call,
            // but VPhoneGaGa's known `su -c` implementation supports the persistent path.
            return runOneShot(command, timeoutMs);
        }
    }

    /** Primarily useful for tests/process teardown; normal app flow intentionally keeps root alive. */
    static void close() {
        synchronized (LOCK) {
            destroySessionLocked();
        }
    }

    private static boolean ensureSessionLocked() {
        if (sessionAliveLocked() && sessionInput != null && sessionOutput != null) return true;
        destroySessionLocked();

        try {
            // We already know this virtual Android supports `su -c ...`. Running `sh`
            // as the command leaves a root shell attached to our stdin/stdout.
            session = new ProcessBuilder("su", "-c", "sh")
                    .redirectErrorStream(true)
                    .start();
            sessionInput = new BufferedWriter(new OutputStreamWriter(session.getOutputStream(), "UTF-8"));
            sessionOutput = new LinkedBlockingQueue<String>();
            final BufferedReader reader = new BufferedReader(new InputStreamReader(session.getInputStream(), "UTF-8"));
            final BlockingQueue<String> queue = sessionOutput;
            sessionDrain = new Thread(new Runnable() {
                @Override public void run() {
                    try {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            queue.offer(line);
                        }
                    } catch (IOException ignored) {
                    } finally {
                        try { reader.close(); } catch (IOException ignored) {}
                    }
                }
            }, "td-root-session-out");
            sessionDrain.setDaemon(true);
            sessionDrain.start();
            sessionMode = "persistent su -c sh";

            Result probe = executePersistentLocked("id", 15000);
            if (probe.ok() && probe.output.indexOf("uid=0") >= 0) {
                cachedRoot = true;
                return true;
            }
        } catch (Throwable ignored) {
            // Fall through to compatibility one-shot mode.
        }

        destroySessionLocked();
        sessionMode = "one-shot fallback";
        return false;
    }

    private static Result executePersistentLocked(String command, long timeoutMs) {
        if (!sessionAliveLocked() || sessionInput == null || sessionOutput == null) {
            destroySessionLocked();
            return new Result(127, "root session unavailable");
        }

        // Drop any asynchronous residue from a previous background child before starting
        // a framed command. Root helper processes redirect their own stdout/stderr to file.
        sessionOutput.clear();
        long id = COMMAND_ID.getAndIncrement();
        String marker = "__TDNS_END_" + id + "_" + Long.toHexString(System.nanoTime()) + "__";
        String wrapped = "( " + command + " ); __tdns_rc=$?; printf '\\n" + marker + ":%s\\n' \"$__tdns_rc\"";

        try {
            sessionInput.write(wrapped);
            sessionInput.newLine();
            sessionInput.flush();
        } catch (Throwable e) {
            destroySessionLocked();
            return new Result(127, e.getClass().getSimpleName() + ": " + safe(e.getMessage()));
        }

        StringBuilder captured = new StringBuilder();
        long deadline = System.currentTimeMillis() + Math.max(1000L, timeoutMs);
        while (System.currentTimeMillis() < deadline) {
            long remaining = deadline - System.currentTimeMillis();
            String line = null;
            try {
                line = sessionOutput.poll(Math.min(150L, Math.max(1L, remaining)), TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                destroySessionLocked();
                return new Result(130, append(captured.toString().trim(), "root command interrupted"));
            }

            if (line != null) {
                int markerPos = line.indexOf(marker + ":");
                if (markerPos >= 0) {
                    String before = line.substring(0, markerPos).trim();
                    appendLimited(captured, before);
                    String rcText = line.substring(markerPos + marker.length() + 1).trim();
                    int code;
                    try { code = Integer.parseInt(rcText); }
                    catch (NumberFormatException ignored) { code = 127; }
                    String text = captured.toString().trim();
                    if (captured.length() >= MAX_CAPTURE) text += "\n[output truncated]";
                    return new Result(code, text);
                }
                appendLimited(captured, line);
            } else if (!sessionAliveLocked()) {
                destroySessionLocked();
                return new Result(127, append(captured.toString().trim(), "root session exited"));
            }
        }

        // A wedged root command must not poison every future command. Killing the one
        // session may cause a single new grant toast next time, but avoids permanent hangs.
        destroySessionLocked();
        return new Result(124, append(captured.toString().trim(), "root command timeout"));
    }

    private static Result runOneShot(String command, long timeoutMs) {
        Process process = null;
        StreamCollector collector = null;
        Thread drain = null;
        try {
            process = new ProcessBuilder("su", "-c", command)
                    .redirectErrorStream(true)
                    .start();

            collector = new StreamCollector(process.getInputStream());
            drain = new Thread(collector, "td-root-oneshot-out");
            drain.setDaemon(true);
            drain.start();

            long end = System.currentTimeMillis() + timeoutMs;
            int code = Integer.MIN_VALUE;
            while (System.currentTimeMillis() < end) {
                try {
                    code = process.exitValue();
                    break;
                } catch (IllegalThreadStateException stillRunning) {
                    try {
                        Thread.sleep(60);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            if (code == Integer.MIN_VALUE) {
                process.destroy();
                joinQuietly(drain, 800);
                return new Result(124, append(collector == null ? "" : collector.text(), "root command timeout"));
            }

            joinQuietly(drain, 1200);
            String output = collector == null ? "" : collector.text();
            if (code == 0 && output.indexOf("uid=0") >= 0) cachedRoot = true;
            return new Result(code, output);
        } catch (Throwable e) {
            return new Result(127, e.getClass().getSimpleName() + ": " + safe(e.getMessage()));
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static boolean sessionAliveLocked() {
        if (session == null) return false;
        try {
            session.exitValue();
            return false;
        } catch (IllegalThreadStateException running) {
            return true;
        }
    }

    private static void destroySessionLocked() {
        if (sessionInput != null) {
            try { sessionInput.close(); } catch (IOException ignored) {}
        }
        if (session != null) {
            try { session.destroy(); } catch (Throwable ignored) {}
        }
        joinQuietly(sessionDrain, 500);
        session = null;
        sessionInput = null;
        sessionOutput = null;
        sessionDrain = null;
        cachedRoot = false;
        if (!"one-shot fallback".equals(sessionMode)) sessionMode = "not-open";
    }

    private static void appendLimited(StringBuilder captured, String line) {
        if (line == null || line.length() == 0 || captured.length() >= MAX_CAPTURE) return;
        if (captured.length() > 0) captured.append('\n');
        int remaining = MAX_CAPTURE - captured.length();
        if (line.length() <= remaining) captured.append(line);
        else captured.append(line.substring(0, remaining));
    }

    private static void joinQuietly(Thread thread, long timeoutMs) {
        if (thread == null) return;
        try {
            thread.join(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String append(String a, String b) {
        if (a == null || a.length() == 0) return b;
        return a + "\n" + b;
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value;
    }

    private static final class StreamCollector implements Runnable {
        private final InputStream input;
        private final ByteArrayOutputStream captured = new ByteArrayOutputStream();

        StreamCollector(InputStream input) {
            this.input = input;
        }

        @Override public void run() {
            byte[] buf = new byte[2048];
            try {
                int n;
                while ((n = input.read(buf)) != -1) {
                    synchronized (captured) {
                        int remaining = MAX_CAPTURE - captured.size();
                        if (remaining > 0) captured.write(buf, 0, Math.min(remaining, n));
                    }
                }
            } catch (IOException ignored) {
            } finally {
                try { input.close(); } catch (IOException ignored) {}
            }
        }

        String text() {
            try {
                synchronized (captured) {
                    String value = new String(captured.toByteArray(), "UTF-8").trim();
                    if (captured.size() >= MAX_CAPTURE) value += "\n[output truncated]";
                    return value;
                }
            } catch (Throwable ignored) {
                return "";
            }
        }
    }
}
