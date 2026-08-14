# Changelog

## 1.8.0 (9)

- Fixed the exact v1.7 VPhoneGaGa blocker: app DNS backend reports `UDP=FAIL TCP=OK` on `127.0.0.1:5454`.
- Root resolver mode now requires the proven TCP/5454 backend; UDP/5454 is only an informational probe.
- Native root helper translates Android UDP/53 queries to DNS-over-TCP toward `127.0.0.1:5454`, then returns the DNS response to the original UDP client.
- TCP/53 continues to relay as DNS-over-TCP to the same backend.
- Reduced the nonessential UDP/5454 probe timeout so startup does not wait many seconds for a path already known to be unreliable.
- Native helper READY log now reports `backend=tcp`.
- GitHub native compilation uses `-Wall -Wextra -Werror` for both ARM ABIs.
- Retains v1.7 netId/interface discovery and v1.6 persistent root session / diagnostics-copy fixes.
- Version visible in UI: v1.8.0.
