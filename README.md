# TommyRootDNS v1.5

Root/system DNS-over-HTTPS controller intended for Android 7+ and constrained virtual Android environments.

Default endpoint: `49aa48.dns.nextdns.io` (normalized to NextDNS DoH).

Automatic mode order:

1. Root iptables/netfilter interception when kernel NAT is usable.
2. Root resolver bridge: local DNS53 as root -> app DoH proxy.
   - Android per-network `setnetdns` when a netId can be resolved.
   - legacy interface resolver commands when supported.
   - legacy `net.dns*` system-property mode for virtual/vendor stacks that expose DNS only through properties.
3. DNS-only `VpnService` when TUN is available.

On kernels proven to have no TUN driver, v1.5 does not waste time retrying VPN.

## Build

Push the project to GitHub. `.github/workflows/build-apk.yml` builds minified/obfuscated APK artifacts. The project intentionally keeps `minSdk 24` and a legacy target behavior for sideload/root use.
