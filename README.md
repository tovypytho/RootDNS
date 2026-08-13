# Tommy RootDNS v1.1

Minimal rooted Android DNS app for Android 7.0+ (API 24), intended for rooted virtual Android environments such as VPhoneGaGa. The UI keeps the **Tommy** watermark at the top. Default DNS is `49aa48.dns.nextdns.io`, normalized internally to NextDNS DNS-over-HTTPS.

## v1.1 changes

- Exact iptables/root failure text is preserved instead of only showing a numeric code.
- Added **RUN DIAGNOSTICS** and **COPY DIAGNOSTICS** in the app.
- Probes root UID, SELinux state, Linux capabilities, ABI, netfilter tables, IPv4 NAT, IPv6 NAT, chain creation, and REDIRECT support.
- Tries several IPv4 backends: `/system/bin/iptables`, `/system/xbin/iptables`, `/vendor/bin/iptables`, PATH `iptables`, and `busybox iptables`.
- Same style of fallback probing for `ip6tables`.
- No longer depends on `xt_owner --uid-owner`; DoH traffic is HTTPS/443 while interception only matches port 53.
- Uses a dedicated `TOMMY_DNS` chain when possible.
- If a vendor iptables build can modify OUTPUT but cannot reliably use a custom chain, the app tries exact direct OUTPUT rules.
- Tries `REDIRECT` first and `DNAT 127.0.0.1:5454` as an IPv4 compatibility fallback.
- Cleanup removes only TommyRootDNS rules; it never performs a global `iptables -F`.
- Root-shell output is drained while commands execute to avoid pipe-buffer stalls and is capped before storing diagnostics.

## What it does

1. Requests root using `su`.
2. Starts a local UDP + TCP DNS proxy on `127.0.0.1:5454`.
3. Bootstraps the configured DoH hostname before DNS interception is enabled.
4. Forwards DNS messages over HTTPS/443.
5. Redirects standard TCP/UDP port 53 traffic to the local proxy using root/netfilter rules.
6. Keeps a foreground service and watchdog running; if the DoH proxy repeatedly fails, interception is removed so normal DNS is restored.
7. Optionally starts on boot.

Apps that use their own DoH/DoT, VPN, or hard-coded destination IPs do not necessarily use port 53 and therefore cannot be guaranteed to pass through this interception.

## VPhoneGaGa diagnostics

If **ENABLE DNS** fails, press **RUN DIAGNOSTICS**. The report includes the actual command result, for example:

- `Permission denied` / operation not permitted → guest root likely lacks netfilter capability such as `CAP_NET_ADMIN`.
- `Table does not exist` → the virtual kernel likely does not expose the IPv4/IPv6 NAT table.
- `not found` → that iptables binary is unavailable; the app will continue trying fallback locations.
- `No chain/target/match by that name` → a kernel/netfilter target such as `REDIRECT` is missing; v1.1 also tries IPv4 DNAT where appropriate.

The probe chain is never attached to OUTPUT, and is deleted after the test.

## GitHub Actions build

This ZIP already includes:

`.github/workflows/build-apk.yml`

It is designed for GitHub web upload: no local Gradle wrapper is required.

1. Upload the **contents** of this project to the repository root.
2. Commit to `main`/`master`, or open **Actions → Build TommyRootDNS APK → Run workflow**.
3. Download the `TommyRootDNS-apk` artifact.
4. Without release-signing secrets, install `TommyRootDNS-test-obfuscated.apk`.

The project currently uses:

- minSdk 24 (Android 7.0)
- targetSdk 28 intentionally for this legacy/root sideload use case
- compileSdk 35
- JDK 17 in CI
- Gradle 8.13 in CI
- AGP 8.13.2
- R8 minification/optimization + resource shrinking

The source itself disables only the `ExpiredTargetSdkVersion` lint check so the legacy target does not block a sideload build.

## Optional stable release signing

Add these GitHub Actions secrets:

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

When configured, the release is signed with your key and its certificate SHA-256 can be compiled into the integrity check. Do not commit your keystore or passwords.

## Hardening

- R8 shrinking/optimization/identifier obfuscation.
- Resource shrinking.
- Class repackaging.
- Source filename metadata renamed.
- Test and release APKs are non-debuggable.
- `allowBackup=false` and cleartext app traffic disabled.
- Optional signing-certificate self-check for signed release builds.

No Android APK can be made literally impossible to decompile or patch. Keeping the repository private matters more than APK obfuscation if the original source must remain secret.
