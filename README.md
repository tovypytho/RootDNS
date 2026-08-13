# Tommy RootDNS

Minimal rooted Android DNS app for Android 7.0+ (API 24). The UI includes a **Tommy** watermark at the top. The default value is `49aa48.dns.nextdns.io`; internally it is normalized to the corresponding NextDNS DNS-over-HTTPS endpoint.

## What it does

- Requests root through `su`.
- Starts a local UDP + TCP DNS proxy on `127.0.0.1:5454`.
- Forwards raw DNS messages to a HTTPS DoH endpoint.
- Creates its own `TOMMY_DNS` iptables NAT chain and redirects standard TCP/UDP port 53 traffic to the local proxy.
- Resolves the DoH hostname before enabling interception, caches the bootstrap IPs, then connects directly to those IPs while keeping the original hostname for TLS SNI/certificate verification. This avoids Android 7 resolver recursion.
- Adds an app-UID exemption when `xt_owner` is available, but does not require it.
- Applies IPv6 interception when the virtual kernel supports `ip6tables` NAT + REDIRECT.
- Foreground service + health watchdog; after three consecutive DoH health failures it removes interception rules to restore normal DNS.
- Optional start-on-boot.

Apps that use their own DoH/DoT, their own VPN, or hard-coded destination IPs do not necessarily use system DNS and therefore cannot be guaranteed to pass through port-53 interception.

## GitHub Actions build

1. Create a **private** GitHub repository if you want the original source to stay private.
2. Upload all files from this project to the repository root.
3. Push to `main`/`master`, or open **Actions → Build APK → Run workflow**.
4. Open the completed workflow and download the `TommyRootDNS-apk` artifact.
5. Without signing secrets, install `TommyRootDNS-test-obfuscated.apk`.

The workflow uses JDK 17, Gradle 8.13, Android SDK 35 and AGP 8.13.2. Both debug/test and release variants have R8 minification/optimization enabled. The test APK is also set `debuggable=false`.

### Stable release signing (recommended)

A GitHub-hosted runner is disposable, so a default debug signing key can change between runs. For an APK that can be upgraded in-place, create your own keystore and add these GitHub repository **Actions secrets**:

- `ANDROID_KEYSTORE_BASE64` — base64 of the `.jks` file.
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

When all four are present, the workflow signs the release APK with that key and automatically compiles the signing certificate SHA-256 into the release build. At runtime, a mismatched re-signed/repacked build refuses to enable root DNS interception.

Example for creating a keystore locally:

```bash
keytool -genkeypair -v -keystore tommy-release.jks -alias tommy \
  -keyalg RSA -keysize 3072 -validity 10000
base64 -w 0 tommy-release.jks
```

Do **not** commit the keystore or its passwords to the repository.

## Hardening included

The APK output is hardened as far as a normal Gradle/R8 build can reasonably go without a commercial protector:

- R8 code shrinking, optimization and identifier obfuscation.
- Resource shrinking + AGP 8.13 optimized resource shrinking.
- Class repackaging to a short package.
- Source filename metadata renamed and normal debug logs stripped.
- Release and test APKs are non-debuggable.
- Default NextDNS endpoint strings are stored encoded and reconstructed at runtime rather than in `strings.xml`.
- `allowBackup=false` and cleartext network traffic disabled.
- Optional release certificate self-check when CI signing is configured.

No Android APK can be made literally impossible to decompile or patch. If the repository is public, anyone already has the original source; use a private repository if source secrecy matters. R8 primarily raises the reverse-engineering cost of the **compiled APK**.

## Compatibility notes

Target environment: rooted Android 7.0/7.1 virtual device. The app itself is Java-only, so the same APK is architecture-independent and does not require separate `armeabi-v7a` or `arm64-v8a` native binaries.

The kernel must provide:

- `su`
- `iptables` with the `nat` table and `REDIRECT` target

IPv6 interception is best-effort because some Android 7 kernels do not expose IPv6 NAT REDIRECT.

## First test in VPhoneGaGa

1. Install the test or signed release APK.
2. Open it and press **CHECK ROOT**; approve the root prompt.
3. Leave the default `49aa48.dns.nextdns.io` value.
4. Press **ENABLE DNS**.
5. Wait for status `Protected • IPv4` or `Protected • IPv4 + IPv6`.
6. Test a browser/app and verify queries from the NextDNS dashboard for profile `49aa48`.
7. Press **DISABLE** before uninstalling the app.

If `iptables` fails, the virtual kernel may be missing the NAT table or REDIRECT target. IPv6 failure alone is non-fatal; the UI will report IPv4-only protection.
