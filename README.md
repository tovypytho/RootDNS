# TommyRootDNS v1.7

Root/system DNS switcher for Android 7+ virtual/rooted environments. Default endpoint remains `49aa48.dns.nextdns.io` (NextDNS profile `49aa48`).

## v1.7 focus: fix localhost:53 bridge

Diagnostics from VPhoneGaGa showed that netId `100`, DNS servers, and the active network are visible, but the old `app_process` helper received a PID and never answered on `127.0.0.1:53`. v1.7 replaces that fragile Java/app_process bridge with a tiny native ARM helper built by GitHub Actions for both `arm64-v8a` and `armeabi-v7a`.

The native helper is packaged inside the universal APK, copied by the persistent root shell to `/data/local/tmp/tommy_dns53`, binds UDP+TCP `127.0.0.1:53`, and forwards DNS to the normal app DoH proxy on `127.0.0.1:5454`.

Additional v1.7 changes:
- validates `127.0.0.1:5454` over UDP/TCP before starting the privileged bridge;
- waits for a native `READY` marker and checks that the helper PID is alive;
- records native helper startup/bind/forwarding errors in diagnostics;
- parses the actual interface and DNS from the active `dumpsys connectivity` block (expected `eth0` on the tested VPhoneGaGa) and parses `/proc/net/route` in Java instead of depending on `awk`;
- treats netd `5xx` protocol replies as failures even when the `ndc` process exits with code 0;
- positively skips VPN when the persistent root session confirms that neither `/dev/tun` nor the kernel TUN driver exists;
- keeps the v1.6 persistent `su -c sh` session to prevent repeated Superuser-granted toast spam.

## GitHub build

Upload the whole project to GitHub. `.github/workflows/build-apk.yml` installs Android NDK 26.3, compiles the ARM64 and ARMv7 DNS53 helper, builds the obfuscated APKs, and uploads `TommyRootDNS-v1.7-apk`.

The installable test APK is `TommyRootDNS-v1.7-test-obfuscated.apk`.
