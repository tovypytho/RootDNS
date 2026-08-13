# Changelog

## 1.3.0
- Android 7/VPhoneGaGa TUN compatibility pass.
- Removed primary VPN MTU 32767.
- Added three VPN establish profiles.
- Added `/dev/tun` diagnostics and narrow root-assisted repair when kernel TUN exists but the device node is missing.
- Improved exact VPN establish error logging.

## 1.2.0
- Added automatic VPN DNS fallback when iptables NAT is unavailable.
