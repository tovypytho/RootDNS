# TommyRootDNS v1.9

Root/system DNS switcher for Android 7+ rooted/virtual environments. Default endpoint: `49aa48.dns.nextdns.io`.

## v1.9 focus: vendor SELinux bind denial on DNS port 53

The v1.8 VPhoneGaGa diagnostics finally reached the privileged bridge and exposed the actual blocker:

- Android default network is available: `netId=100`, interface `eth0`.
- Original DNS is `180.250.245.142` / `180.250.245.133`.
- App proxy `127.0.0.1:5454` answers TCP DNS.
- Native helper is copied and executed successfully as uid 0.
- The native helper then fails on `bind(...:53)` with `errno=13 Permission denied` while SELinux is Enforcing.
- Guest kernel still exposes neither netfilter tables nor TUN, so resolver + local DNS53 remains the only practical in-guest path.

v1.9 does not assume that uid=0 is sufficient. It treats privileged port binding as a separate compatibility problem and tries a layered strategy:

1. Native helper under the persistent root shell.
2. Native helper under a **fresh `su -c` execution domain**. Some vendor root managers keep `su -c sh` in a restricted SELinux domain but execute a direct command in a more privileged root domain.
3. Native helper first tries `127.0.0.1:53`, then `0.0.0.0:53` with a strict userspace loopback-client filter. This can bypass vendor policies that deny loopback `node_bind` while still keeping LAN clients rejected.
4. If `magiskpolicy` / compatible `supolicy` exists, Tommy reads the **helper process SELinux context**, restores the standard `netdomain` attribute when possible, applies narrow DNS-port/loopback/TCP-backend rules, and can derive additional socket-only rules from matching AVC denials. It never turns unrelated AVCs into blanket allows.
5. If still denied, Tommy briefly switches SELinux to Permissive **only while bind/listen is performed**, immediately restores Enforcing, then performs real UDP+TCP DNS probes. If the already-bound sockets continue working, SELinux stays Enforcing for normal operation.
6. Optional **Extreme compatibility** is a final user opt-in. If all safer paths fail and TUN is known unavailable, the foreground app now opens an explicit compatibility approval dialog instead of ending at a generic “no backend” status. If approved, SELinux can remain Permissive only while DNS is active. A root watchdog restores Enforcing and kills the helper if either the APK process or helper disappears. Disable/failsafe also restores Enforcing.

The DNS data path remains:

```text
Android resolver UDP/TCP :53
        -> SELinux-aware native root bridge
        -> DNS-over-TCP 127.0.0.1:5454
        -> DoH
        -> NextDNS profile 49aa48
```

The native bridge can bind wildcard as a compatibility fallback, but it rejects every client whose source address is not loopback (127/8), so it is not intentionally exposed as a LAN DNS server.

Persistent `su -c sh` remains the normal root transport to avoid Superuser toast spam. The fresh-su strategy is attempted only after a real port-53 EACCES and should add at most one extra grant notification per enable attempt.

## GitHub build

Upload the whole project. `.github/workflows/build-apk.yml` installs Android NDK 26.3, compiles the native helper for `arm64-v8a` and `armeabi-v7a`, builds the R8-minified APKs, and uploads artifact `TommyRootDNS-v1.9-apk`.

Installable test APK: `TommyRootDNS-v1.9-test-obfuscated.apk`.
