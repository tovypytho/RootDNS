# Changelog

## 1.5.0

- Root resolver no longer requires `ConnectivityManager.getActiveNetwork()` to succeed.
- Starts the root localhost:53 bridge before resolver/network detection.
- Detects Android 7 default `netId` from `dumpsys connectivity` when public APIs return null.
- Detects default interface from `/proc/net/route` / `ip route`.
- Resolver strategy order: `ndc resolver setnetdns`, legacy `setifdns`/`setdefaultif`, then `net.dns1/net.dns2` properties.
- Property fallback increments `net.dnschange` and broadcasts `CLEAR_DNS_CACHE`.
- Saves/restores resolver strategy, interface, DNS properties, and DNS-change counter.
- Skips VPN fallback when `/dev/tun` is absent and `/proc/misc` confirms no TUN driver.
- More detailed resolver diagnostics: route table, connectivity dump head, `ndc resolver` probe, helper status/log.
- Version visible in UI: v1.5.0.
