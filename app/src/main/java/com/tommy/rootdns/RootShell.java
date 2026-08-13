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
            this.output = output;
        }
        boolean ok() { return code == 0; }
    }

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
        try {
            process = new ProcessBuilder("su", "-c", command)
                    .redirectErrorStream(true)
                    .start();

            long end = System.currentTimeMillis() + timeoutMs;
            int code = Integer.MIN_VALUE;
            while (System.currentTimeMillis() < end) {
                try {
                    code = process.exitValue();
                    break;
                } catch (IllegalThreadStateException stillRunning) {
                    try { Thread.sleep(80); } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            if (code == Integer.MIN_VALUE) {
                process.destroy();
                return new Result(124, "root command timeout");
            }

            return new Result(code, readAll(process.getInputStream()));
        } catch (Throwable e) {
            return new Result(127, e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static String readAll(InputStream input) throws IOException {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n;
            while ((n = input.read(buf)) != -1) out.write(buf, 0, n);
            return new String(out.toByteArray(), "UTF-8");
        } finally {
            input.close();
        }
    }
}
