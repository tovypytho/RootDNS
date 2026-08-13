# Changelog

## 1.2.0
- Added automatic DNS mode selection.
- Keeps root/iptables interception when the guest kernel exposes usable netfilter NAT.
- Adds Android `VpnService` DNS-only fallback for VPhoneGaGa/Android guests with no `filter`/`nat` tables.
- VPN mode routes only synthetic DNS `10.77.0.2/32` into the TUN; ordinary app traffic is not tunneled.
- Standard Android system DNS UDP queries are converted to DoH and sent to the configured endpoint.
- First VPN use requests the standard Android VPN consent dialog.
- Added active MODE indicator and VPN permission state to diagnostics.
- Boot restore supports previously granted VPN mode.
- Retains NextDNS default `49aa48.dns.nextdns.io`, root diagnostics, R8 shrinking/obfuscation, optional signing pinning, and GitHub Actions build.

## 1.1.0
- Added detailed iptables/netfilter diagnostics and multiple backend probes.
- Added REDIRECT/DNAT compatibility attempts.
