# TommyRootDNS 1.2

Minimal Android 7+ DNS-over-HTTPS app designed for rooted virtual Android environments such as VPhoneGaGa.

## What changed in v1.2

The tested VPhoneGaGa guest had root and full-looking capabilities, but its kernel exposed no usable iptables `filter` or `nat` tables. A different iptables binary cannot fix a kernel feature that is absent. v1.2 therefore uses **Automatic mode**:

1. Try the existing root DNS53 interception with iptables/netfilter.
2. If the kernel cannot provide NAT, fall back to an Android `VpnService` DNS-only tunnel.
3. VPN mode sets a synthetic DNS server (`10.77.0.2`) and routes only that address into the TUN.
4. Standard Android DNS UDP requests are extracted and sent to the configured DoH endpoint.
5. Normal web/app traffic is not routed through TommyRootDNS.

Default DNS profile:

`49aa48.dns.nextdns.io`

which is normalized internally to the NextDNS DoH endpoint for profile `49aa48`.

## Important VPN-mode scope

VPN fallback is intentionally DNS-only. It covers apps that use Android's normal resolver, which is the usual system-wide DNS path. Apps that implement their own DoH/DoT, use a separate VPN, connect directly to hard-coded IP addresses, or open direct DNS sockets to unrelated DNS server IPs can bypass this DNS-only design.

The VPN fallback currently handles IPv4 UDP DNS packets sent to Tommy's synthetic DNS server. IPv6 application traffic is explicitly allowed to remain on the normal network. Large/rare DNS-over-TCP fallback is not implemented in this version.

## Android compatibility

- minSdk: 24 (Android 7.0)
- targetSdk: 28 (legacy/sideload behavior retained intentionally)
- compileSdk: 35
- Java-only APK; no native ABI dependency
- usable on 32-bit or 64-bit Android guests

## GitHub Actions build

The repository includes:

`.github/workflows/build-apk.yml`

Upload the project contents to the root of a GitHub repository. Then open **Actions → Build TommyRootDNS APK → Run workflow**.

The workflow builds an installable, non-debuggable, minified/obfuscated test APK and an optional release APK.

### Optional release signing secrets

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

When signing secrets are supplied, the release certificate SHA-256 is compiled into the build for the existing integrity check.

## First run on VPhoneGaGa

1. Install the APK.
2. Open TommyRootDNS.
3. Tap **ENABLE DNS**.
4. Automatic mode tries root/netfilter.
5. On the known VPhoneGaGa kernel with no NAT tables, Android should display the system VPN connection permission dialog.
6. Approve it.
7. Status should become `Protected • VPN DNS`.

Run **RUN DIAGNOSTICS** and copy the result if activation fails.

## Hardening

Release/test builds keep R8 optimization, shrinking, class/method renaming, class repackaging, source filename renaming, resource shrinking, non-debuggable builds, no backups, no cleartext traffic, basic debugger detection, package integrity checks, and optional certificate pinning.

No Android APK can be made literally impossible to reverse engineer; these measures raise the cost of casual decompilation/repacking.
