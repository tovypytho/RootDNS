# Changelog

## 1.7.0 (8)

- Replaced the primary `app_process` root port-53 bridge with an NDK-built native helper.
- Added universal native helper builds for `arm64-v8a` and `armeabi-v7a`.
- Native helper binds both UDP and TCP `127.0.0.1:53` and forwards to the app proxy on `127.0.0.1:5454`.
- Added helper staging/copy to `/data/local/tmp`, READY/PID checks, and detailed native error logging.
- Added pre-bridge UDP/TCP health checks for the app-side port 5454 proxy.
- Fixed default-interface detection by parsing the active `dumpsys connectivity` block and `/proc/net/route` in Java; avoids false interface values such as `sh:` when `awk` is missing.
- Resolver command validation now rejects netd 5xx replies.
- TUN unavailability detection now uses the persistent root shell, preventing useless VPN retries on the tested kernel.
- Retains persistent root session and reliable diagnostics copy from v1.6.
- Version visible in UI: v1.7.0.
