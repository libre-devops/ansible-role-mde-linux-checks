# Fixtures

What the stub mdatp command (`molecule/resources/mdatp-stub.py`) answers with.

- `rhel9-unlicensed/`: output captured on 15 November 2026 from a RHEL 9.8 Azure VM running mdatp 101.26101.0000 with real-time protection on (`mdatp_managed.json`), online but not onboarded. Its device ids were replaced with made-up ones.
- `broken/`: the same, with real-time protection unavailable, the netlink fallback event provider, a conflicting application, a folder permission issue and one unreachable URL.

`tests/unit/fixtures/rhel9-online-unlicensed.json` is the role's own probe of that VM, ids replaced the same way. The readiness fields (`architecture`, `os_release`, `systemd`, `kernel_config`, `mount_options`, `fanotify_users`, `iptables`) were added to the probe after the capture, so they were filled in from what the VM had: RHEL 9.8 on x86_64, `/var` on its own file system, and Defender's own blocking fanotify use.
