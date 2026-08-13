package com.tommy.rootdns;

final class ObfStrings {
    private static volatile int runtimeSalt;

    private ObfStrings() {}

    static String defaultPrivateDnsHost() {
        return decode(new int[]{
                93, 177, 198, 167, 209, 60, 13, 38, 15, 243, 177, 208,
                184, 132, 111, 94, 55, 11, 185, 223, 186
        }, 105);
    }

    static String nextDnsDohBase() {
        return decode(new int[]{
                22, 233, 200, 171, 137, 35, 23, 120, 18, 251, 199, 253,
                156, 116, 72, 59, 10, 227, 223, 229, 131, 102, 7
        }, 126);
    }

    private static String decode(int[] data, int seed) {
        char[] out = new char[data.length];
        for (int i = 0; i < data.length; i++) {
            int key = (seed + (i * 31) + runtimeSalt) & 0xFF;
            out[i] = (char) ((data[i] ^ key) & 0xFF);
        }
        return new String(out);
    }
}
