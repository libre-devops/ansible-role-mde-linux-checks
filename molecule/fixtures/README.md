# Fixtures

What the stub mdatp command (`molecule/resources/mdatp-stub.py`) answers with.

- `rhel9-unlicensed/`: output captured on 15 November 2026 from a RHEL 9.8 Azure VM running mdatp 101.26101.0000 with real-time protection on (`mdatp_managed.json`), online but not onboarded. Its device ids were replaced with made-up ones.
- `broken/`: the same, with real-time protection unavailable, the netlink fallback event provider, a conflicting application, a folder permission issue and one unreachable URL.
