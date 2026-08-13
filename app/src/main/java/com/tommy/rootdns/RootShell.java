package com.tommy.rootdns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

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

    private RootShell() {}

    static boolean hasRoot() {
        Result result = run("id", 8000);
        return result.ok() && result.output.indexOf("uid=0") >= 0;
    }

    static Result run(String command) {
        return run(command, 12000);
    }

    static Result run(String command, long timeoutMs) {
        Process process = null;
        StreamCollector collector = null;
        Thread drain = null;
        try {
            process = new ProcessBuilder("su", "-c", command)
                    .redirectErrorStream(true)
                    .start();

            collector = new StreamCollector(process.getInputStream());
            drain = new Thread(collector, "td-root-out");
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
            return new Result(code, collector == null ? "" : collector.text());
        } catch (Throwable e) {
            return new Result(127, e.getClass().getSimpleName() + ": " + safe(e.getMessage()));
        } finally {
            if (process != null) process.destroy();
        }
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
