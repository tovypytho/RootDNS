# TommyRootDNS 1.3

Root/VPN DNS-over-HTTPS utility for Android 7+ with the default NextDNS profile `49aa48.dns.nextdns.io`.

## What changed in v1.3

The VPhoneGaGa test guest grants root but exposes no iptables/netfilter tables. v1.2 correctly fell back to Android `VpnService`, but the VPN interface failed with `Cannot create interface`. v1.3 targets that failure directly:

- removes the forced MTU 32767 from the primary VPN profile;
- retries conservative VPN profiles (`/32`, then `/24`, then MTU 1500 `/24`);
- removes unnecessary IPv6/disallowed-app VPN configuration from the DNS-only TUN;
- diagnoses `/dev/tun`, `/proc/misc`, kernel TUN configuration, and `/proc/net/dev`;
- if the kernel registers TUN but `/dev/tun` is missing, root mode can recreate the standard `10:200` device node and attempt the Android `tun_device` SELinux label;
- records the exact VPN profile and exception for every establish attempt.

The app still tries root/iptables first and automatically falls back to VPN DNS when netfilter is unavailable.
