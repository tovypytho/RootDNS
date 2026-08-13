# Changelog

## 1.4.0

- Added `ROOT_RESOLVER` fallback for Android kernels without netfilter and TUN.
- Added root `app_process` DNS53 bridge: `127.0.0.1:53 -> 127.0.0.1:5454`.
- Added active Android network/netId discovery using `ConnectivityManager`.
- Added netd resolver override and cache flush through `ndc resolver setnetdns`.
- Added backup/restore for original active-network DNS and legacy `net.dns1/net.dns2` properties.
- Added resolver watchdog and network re-application.
- Added root-resolver diagnostics (netId, LinkProperties DNS, `ndc`, `app_process`, helper pid/log, localhost:53 probe).
- Added visible app version beneath the Tommy watermark.
- Kept R8 hardening, iptables mode, VPN fallback, and NextDNS default profile.
