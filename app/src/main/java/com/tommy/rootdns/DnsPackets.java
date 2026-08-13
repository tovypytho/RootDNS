package com.tommy.rootdns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;

final class DnsPackets {
    private static final Random RANDOM = new Random();

    private DnsPackets() {}

    static byte[] aQuery(String host) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int id = RANDOM.nextInt(65536);
            out.write((id >>> 8) & 0xFF);
            out.write(id & 0xFF);
            out.write(0x01); // recursion desired
            out.write(0x00);
            out.write(0x00); out.write(0x01); // QDCOUNT
            out.write(0x00); out.write(0x00); // ANCOUNT
            out.write(0x00); out.write(0x00); // NSCOUNT
            out.write(0x00); out.write(0x00); // ARCOUNT

            String[] labels = host.split("\\.");
            for (String label : labels) {
                byte[] bytes = label.getBytes("US-ASCII");
                if (bytes.length == 0 || bytes.length > 63) throw new IOException("Bad label");
                out.write(bytes.length);
                out.write(bytes);
            }
            out.write(0x00);
            out.write(0x00); out.write(0x01); // A
            out.write(0x00); out.write(0x01); // IN
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
