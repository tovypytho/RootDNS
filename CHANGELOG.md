# Changelog

## 1.9.0 (10)

- Fixed the next concrete VPhoneGaGa blocker from v1.8: native root helper executes but `bind UDP 127.0.0.1:53` returns `errno=13 Permission denied` under SELinux Enforcing.
- Added privileged-bind strategy ladder instead of assuming uid=0 means port 53 is usable.
- Added fresh `su -c` execution-domain retry only on EACCES; persistent root remains the default to prevent Superuser toast spam.
- Native helper now logs its uid/gid/SELinux process context before bind.
- Native helper tries loopback bind first, then wildcard bind with strict rejection of all non-loopback UDP/TCP clients.
- Added helper-context-aware live `magiskpolicy`/`supolicy` repair: `netdomain`, narrow DNS-port/loopback/backend socket rules, plus whitelisted network-only rules derived from matching AVC denials.
- Added automatic transient-Permissive bind attempt: Enforcing is restored before resolver probes and normal operation.
- Added opt-in Extreme compatibility for devices where SELinux also blocks traffic after re-enforcing. When safer paths are exhausted and TUN is unavailable, the UI now asks for explicit approval and automatically retries. When used, an independent root watchdog restores Enforcing if the app/helper exits.
- Disable/failsafe and stale-start recovery restore SELinux Enforcing if Tommy previously relaxed it.
- Diagnostics now report root SELinux context, current mode, policy-tool availability, Extreme compatibility state, recent AVC denials, and helper self-context.
- Resolver strategies are now behavior-verified: after each netd/interface/property override Tommy triggers a unique system DNS lookup and requires the native bridge query counter to increase before declaring protection active.
- Retains UDP/53 -> TCP/5454 translation, netId=100/dumpsys discovery, netd/property resolver fallbacks, TUN detection, R8 obfuscation, and universal ARM64/ARMv7 build.
- Version visible in UI: v1.9.0.
