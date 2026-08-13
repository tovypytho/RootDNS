# TommyRootDNS v1.4.0

Rooted Android 7+ DNS-over-HTTPS utility, designed for virtual Android environments such as VPhoneGaGa.

## Automatic mode order

1. **Root + iptables/netfilter** — strongest port-53 interception when kernel NAT is available.
2. **Root resolver mode** — for kernels with no netfilter/TUN. Tommy starts its normal DoH proxy on `127.0.0.1:5454`, launches a very small root `app_process` bridge on `127.0.0.1:53`, and points Android's active netd resolver at `127.0.0.1`.
3. **DNS-only VpnService** — final fallback when Android TUN is available.

Default NextDNS profile: `49aa48.dns.nextdns.io`.

## VPhoneGaGa motivation

The tested Android 7.1.2 environment reports root and broad capabilities, but exposes neither iptables tables nor `/dev/tun`. v1.4 therefore adds a resolver path that does not require either kernel feature.

## GitHub Actions

Upload the entire project to a GitHub repository. The workflow at `.github/workflows/build-apk.yml` builds minified/obfuscated APKs automatically on pushes to `main`/`master` and can also be run manually.

For stable release upgrades, configure the same Android signing key in GitHub Actions secrets:

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

## Important limitation

Root resolver mode changes Android's system resolver for the active network. Apps that implement their own DoH/DoT, use hard-coded IP addresses, or bypass Android's libc/netd resolver are outside that path.
