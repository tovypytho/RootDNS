package com.tommy.rootdns;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal IPv4/UDP packet helper for the DNS-only VpnService mode.
 * The VPN routes only the synthetic DNS server address into the TUN, so
 * non-DNS Internet traffic remains on Android's normal network stack.
 */
final class VpnDnsPacket {
    static final byte[] DNS_IP = new byte[] {10, 77, 0, 2};
    static final String DNS_IP_TEXT = "10.77.0.2";
    static final String TUN_IP_TEXT = "10.77.0.1";

    private static final AtomicInteger IP_ID = new AtomicInteger(0x4250);

    private VpnDnsPacket() {}

    static final class Query {
        final byte[] sourceIp;
        final byte[] destinationIp;
        final int sourcePort;
        final int destinationPort;
        final byte[] dnsMessage;

        Query(byte[] sourceIp, byte[] destinationIp, int sourcePort,
              int destinationPort, byte[] dnsMessage) {
            this.sourceIp = sourceIp;
            this.destinationIp = destinationIp;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.dnsMessage = dnsMessage;
        }
    }

    static Query parseUdpDnsQuery(byte[] packet, int length) {
        if (packet == null || length < 28) return null;
        int version = (packet[0] >>> 4) & 0x0F;
        if (version != 4) return null;

        int ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || length < ihl + 8) return null;
        if ((packet[9] & 0xFF) != 17) return null; // UDP only.

        int fragment = u16(packet, 6);
        if ((fragment & 0x1FFF) != 0) return null; // Ignore non-first fragments.

        int totalLength = u16(packet, 2);
        if (totalLength <= 0 || totalLength > length) totalLength = length;
        if (totalLength < ihl + 8) return null;

        int udp = ihl;
        int srcPort = u16(packet, udp);
        int dstPort = u16(packet, udp + 2);
        if (dstPort != 53) return null;

        byte[] dst = Arrays.copyOfRange(packet, 16, 20);
        if (!Arrays.equals(dst, DNS_IP)) return null;

        int udpLength = u16(packet, udp + 4);
        if (udpLength < 8) return null;
        int payloadLength = Math.min(udpLength - 8, totalLength - ihl - 8);
        if (payloadLength < 12) return null;

        byte[] src = Arrays.copyOfRange(packet, 12, 16);
        byte[] dns = Arrays.copyOfRange(packet, udp + 8, udp + 8 + payloadLength);
        return new Query(src, dst, srcPort, dstPort, dns);
    }

    static byte[] buildUdpResponse(Query query, byte[] dnsResponse) {
        if (query == null || dnsResponse == null || dnsResponse.length < 12) {
            throw new IllegalArgumentException("Invalid DNS response");
        }
        int udpLength = 8 + dnsResponse.length;
        int totalLength = 20 + udpLength;
        if (totalLength > 65535) throw new IllegalArgumentException("DNS packet too large");

        byte[] out = new byte[totalLength];
        out[0] = 0x45; // IPv4, IHL 5.
        out[1] = 0;
        put16(out, 2, totalLength);
        put16(out, 4, IP_ID.getAndIncrement() & 0xFFFF);
        put16(out, 6, 0); // no fragmentation flags/offset
        out[8] = 64;
        out[9] = 17; // UDP
        // checksum at 10..11 filled later.
        System.arraycopy(query.destinationIp, 0, out, 12, 4);
        System.arraycopy(query.sourceIp, 0, out, 16, 4);

        int udp = 20;
        put16(out, udp, 53);
        put16(out, udp + 2, query.sourcePort);
        put16(out, udp + 4, udpLength);
        put16(out, udp + 6, 0);
        System.arraycopy(dnsResponse, 0, out, udp + 8, dnsResponse.length);

        put16(out, 10, checksum(out, 0, 20, 0));
        int pseudo = pseudoHeaderSum(out, udpLength);
        int udpChecksum = checksum(out, udp, udpLength, pseudo);
        if (udpChecksum == 0) udpChecksum = 0xFFFF;
        put16(out, udp + 6, udpChecksum);
        return out;
    }

    static byte[] servFail(byte[] query) {
        if (query == null || query.length < 12) return new byte[0];
        byte[] out = query.clone();
        int flags = u16(out, 2);
        flags |= 0x8000; // QR=response
        flags |= 0x0080; // RA
        flags &= ~0x000F;
        flags |= 0x0002; // SERVFAIL
        put16(out, 2, flags);
        put16(out, 6, 0); // ANCOUNT
        put16(out, 8, 0); // NSCOUNT
        // Keep ARCOUNT/EDNS bytes as received; this is harmless and preserves packet size.
        return out;
    }

    private static int pseudoHeaderSum(byte[] ipv4Packet, int udpLength) {
        long sum = 0;
        sum += u16(ipv4Packet, 12);
        sum += u16(ipv4Packet, 14);
        sum += u16(ipv4Packet, 16);
        sum += u16(ipv4Packet, 18);
        sum += 17;
        sum += udpLength;
        return fold(sum);
    }

    private static int checksum(byte[] data, int offset, int length, int seed) {
        long sum = seed & 0xFFFFL;
        int end = offset + length;
        for (int i = offset; i + 1 < end; i += 2) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            sum = (sum & 0xFFFFL) + (sum >>> 16);
        }
        if ((length & 1) != 0) {
            sum += (data[end - 1] & 0xFF) << 8;
        }
        sum = fold(sum);
        return (~((int) sum)) & 0xFFFF;
    }

    private static int fold(long sum) {
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xFFFFL) + (sum >>> 16);
        }
        return (int) sum & 0xFFFF;
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static void put16(byte[] data, int offset, int value) {
        data[offset] = (byte) ((value >>> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }
}
