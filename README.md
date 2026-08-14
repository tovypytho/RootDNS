# TommyRootDNS v1.8

Root/system DNS switcher for Android 7+ rooted/virtual environments. Default endpoint: `49aa48.dns.nextdns.io`.

## v1.8 focus: VPhoneGaGa UDP backend workaround

The v1.7 diagnostics finally isolated the current failure precisely:

- Android default network is detected: `netId=100`, interface `eth0`.
- Original DNS is detected: `180.250.245.142` and `180.250.245.133`.
- iptables/netfilter is unavailable in the guest kernel.
- TUN is unavailable in the guest kernel.
- The app DNS proxy on `127.0.0.1:5454` answers **TCP DNS**, but the Java UDP listener does not reliably return the probe response:
  `backend 127.0.0.1:5454 UDP=FAIL TCP=OK`.

v1.7 stopped at that point before launching the privileged localhost bridge. v1.8 no longer treats the broken UDP/5454 path as fatal.

The root helper now exposes normal DNS to Android on both UDP and TCP `127.0.0.1:53`, but internally it uses the proven TCP listener on `127.0.0.1:5454`:

```text
Android resolver UDP/53 ─┐
                         ├─> native root bridge 127.0.0.1:53
Android resolver TCP/53 ─┘                │
                                          └─ DNS-over-TCP -> 127.0.0.1:5454
                                                               │
                                                               └─ DoH -> NextDNS
```

This preserves ordinary UDP DNS semantics for Android while avoiding the unreliable app-side UDP socket path.

Other behavior retained:
- persistent `su -c sh` root session to avoid repeated Superuser-granted toast spam;
- native ARM64 + ARMv7 port-53 helper;
- netId / interface discovery through `dumpsys connectivity` and route parsing;
- netd `setnetdns` / legacy interface / `net.dns*` resolver fallbacks;
- automatic DNS restore on disable/failsafe;
- R8 optimization/obfuscation and resource shrinking.

## GitHub build

Upload the whole project. `.github/workflows/build-apk.yml` installs Android NDK 26.3, compiles the native helper for `arm64-v8a` and `armeabi-v7a`, builds the minified APKs, and uploads artifact `TommyRootDNS-v1.8-apk`.

Installable test APK: `TommyRootDNS-v1.8-test-obfuscated.apk`.
