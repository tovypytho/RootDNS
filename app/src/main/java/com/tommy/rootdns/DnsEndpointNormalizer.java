package com.tommy.rootdns;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;

final class DnsEndpointNormalizer {
    private static final String NEXTDNS_SUFFIX = ".dns.nextdns.io";

    private DnsEndpointNormalizer() {}

    static String defaultDisplayValue() {
        return ObfStrings.defaultPrivateDnsHost();
    }

    static String normalize(String raw) {
        String value = raw == null ? "" : raw.trim();
        if (value.length() == 0) {
            value = defaultDisplayValue();
        }

        String lower = value.toLowerCase(Locale.US);
        String endpoint;
        if (lower.startsWith("https://")) {
            endpoint = value;
        } else if (lower.endsWith(NEXTDNS_SUFFIX)) {
            String profile = value.substring(0, value.length() - NEXTDNS_SUFFIX.length());
            endpoint = nextDns(profile);
        } else if (isProfileId(value)) {
            endpoint = nextDns(value);
        } else {
            throw new IllegalArgumentException("Use a HTTPS DoH URL or a NextDNS profile hostname.");
        }

        try {
            URL url = new URL(endpoint);
            if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getHost() == null || url.getHost().length() == 0) {
                throw new IllegalArgumentException("DoH endpoint must use HTTPS.");
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid DoH endpoint.");
        }
        return endpoint;
    }

    private static String nextDns(String profile) {
        if (!isProfileId(profile)) {
            throw new IllegalArgumentException("Invalid NextDNS profile ID.");
        }
        return ObfStrings.nextDnsDohBase() + profile;
    }

    private static boolean isProfileId(String value) {
        if (value == null || value.length() < 3 || value.length() > 64) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
    }
}
