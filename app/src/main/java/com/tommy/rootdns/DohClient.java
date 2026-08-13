package com.tommy.rootdns;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Small HTTP/1.1 DoH client that resolves the upstream only when constructed.
 * After iptables interception is enabled it connects directly to the cached
 * bootstrap IP while still using the original hostname for TLS SNI and
 * certificate verification. This prevents resolver recursion on Android 7.
 */
final class DohClient {
    private final URL endpoint;
    private final InetAddress[] bootstrap;
    private final AtomicInteger cursor = new AtomicInteger();

    DohClient(String endpoint) throws IOException {
        this.endpoint = new URL(endpoint);
        this.bootstrap = InetAddress.getAllByName(this.endpoint.getHost());
        if (bootstrap == null || bootstrap.length == 0) {
            throw new IOException("Could not bootstrap DoH host");
        }
    }

    byte[] query(byte[] dnsMessage) throws IOException {
        IOException last = null;
        int start = Math.abs(cursor.getAndIncrement());
        for (int i = 0; i < bootstrap.length; i++) {
            InetAddress address = bootstrap[(start + i) % bootstrap.length];
            try {
                return queryAddress(address, dnsMessage);
            } catch (IOException e) {
                last = e;
            }
        }
        throw last == null ? new IOException("DoH unavailable") : last;
    }

    private byte[] queryAddress(InetAddress address, byte[] dnsMessage) throws IOException {
        String host = endpoint.getHost();
        int port = endpoint.getPort() > 0 ? endpoint.getPort() : 443;
        String file = endpoint.getFile();
        if (file == null || file.length() == 0) file = "/";
        String hostHeader = port == 443 ? host : host + ":" + port;

        Socket plain = new Socket();
        SSLSocket ssl = null;
        try {
            plain.connect(new InetSocketAddress(address, port), 8000);
            plain.setSoTimeout(10000);

            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            ssl = (SSLSocket) factory.createSocket(plain, host, port, true);
            ssl.setSoTimeout(10000);
            ssl.startHandshake();

            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ssl.getSession())) {
                throw new IOException("DoH TLS hostname verification failed");
            }

            OutputStream out = ssl.getOutputStream();
            String headers = "POST " + file + " HTTP/1.1\r\n" +
                    "Host: " + hostHeader + "\r\n" +
                    "Content-Type: application/dns-message\r\n" +
                    "Accept: application/dns-message\r\n" +
                    "User-Agent: TommyDNS/1\r\n" +
                    "Content-Length: " + dnsMessage.length + "\r\n" +
                    "Connection: close\r\n\r\n";
            out.write(headers.getBytes("ISO-8859-1"));
            out.write(dnsMessage);
            out.flush();

            InputStream in = ssl.getInputStream();
            String status = readLine(in, 4096);
            if (status == null || status.length() == 0) throw new EOFException("No DoH HTTP status");
            String[] parts = status.split(" ", 3);
            if (parts.length < 2) throw new IOException("Bad DoH HTTP status");
            int code;
            try {
                code = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                throw new IOException("Bad DoH HTTP status");
            }

            int contentLength = -1;
            boolean chunked = false;
            boolean dnsContent = false;
            int headerBytes = status.length();
            while (true) {
                String line = readLine(in, 8192);
                if (line == null) throw new EOFException("Short DoH headers");
                headerBytes += line.length();
                if (headerBytes > 32768) throw new IOException("DoH headers too large");
                if (line.length() == 0) break;
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                String name = line.substring(0, colon).trim().toLowerCase(Locale.US);
                String value = line.substring(colon + 1).trim();
                if ("content-length".equals(name)) {
                    try { contentLength = Integer.parseInt(value); } catch (NumberFormatException ignored) {}
                } else if ("transfer-encoding".equals(name) && value.toLowerCase(Locale.US).indexOf("chunked") >= 0) {
                    chunked = true;
                } else if ("content-type".equals(name) && value.toLowerCase(Locale.US).indexOf("application/dns-message") >= 0) {
                    dnsContent = true;
                }
            }

            if (code != 200) throw new IOException("DoH HTTP " + code);
            if (!dnsContent) throw new IOException("Unexpected DoH content type");

            byte[] response;
            if (chunked) {
                response = readChunked(in, 65535);
            } else if (contentLength >= 0) {
                if (contentLength > 65535) throw new IOException("DoH response too large");
                response = readExact(in, contentLength);
            } else {
                response = readUntilEof(in, 65535);
            }

            if (response.length < 12) throw new IOException("Short DNS response");
            if (dnsMessage.length >= 2) {
                response[0] = dnsMessage[0];
                response[1] = dnsMessage[1];
            }
            return response;
        } finally {
            if (ssl != null) {
                try { ssl.close(); } catch (IOException ignored) {}
            } else {
                try { plain.close(); } catch (IOException ignored) {}
            }
        }
    }

    private static String readLine(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int prev = -1;
        while (out.size() <= max) {
            int c = in.read();
            if (c == -1) {
                if (out.size() == 0 && prev == -1) return null;
                break;
            }
            if (prev == '\r' && c == '\n') {
                byte[] bytes = out.toByteArray();
                int len = bytes.length;
                if (len > 0 && bytes[len - 1] == '\r') len--;
                return new String(bytes, 0, len, "ISO-8859-1");
            }
            out.write(c);
            prev = c;
        }
        if (out.size() > max) throw new IOException("HTTP line too long");
        return new String(out.toByteArray(), "ISO-8859-1");
    }

    private static byte[] readChunked(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in, 256);
            if (sizeLine == null) throw new EOFException("Short chunk header");
            int semi = sizeLine.indexOf(';');
            String number = (semi >= 0 ? sizeLine.substring(0, semi) : sizeLine).trim();
            int size;
            try { size = Integer.parseInt(number, 16); }
            catch (NumberFormatException e) { throw new IOException("Bad chunk size"); }
            if (size == 0) {
                // Consume optional trailers.
                while (true) {
                    String trailer = readLine(in, 4096);
                    if (trailer == null || trailer.length() == 0) break;
                }
                break;
            }
            if (size < 0 || out.size() + size > max) throw new IOException("DoH response too large");
            out.write(readExact(in, size));
            String crlf = readLine(in, 2);
            if (crlf == null || crlf.length() != 0) throw new IOException("Bad chunk terminator");
        }
        return out.toByteArray();
    }

    private static byte[] readExact(InputStream in, int length) throws IOException {
        byte[] out = new byte[length];
        int pos = 0;
        while (pos < length) {
            int n = in.read(out, pos, length - pos);
            if (n < 0) throw new EOFException("Short HTTP body");
            pos += n;
        }
        return out;
    }

    private static byte[] readUntilEof(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            if (out.size() + n > max) throw new IOException("DoH response too large");
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
