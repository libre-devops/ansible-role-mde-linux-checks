# Changelog

Notable changes to this role. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- First release.
- Checks of Microsoft Defender for Endpoint on Linux in eight groups: installation, stability, protection, configuration, onboarding, the system, resources and upgrade, each with a stable id and a severity, left in `mde_linux_checks_test_results` in the format `libre_devops.test_results_report` reads.
- Two profiles: `release`, a release test on throwaway machines, and `health`, a health check of devices in use. Tests that act on the host, each its own boolean: a security intelligence update, the connectivity test and a quick scan in both profiles; the EICAR test file (`library/mde_linux_checks_eicar.py`, timed, at the enforcement level's own behaviour, cleaned up afterwards) and a reboot that proves the agent comes back in `release` only.
- Log-based checks (crashes, SELinux denials, the journal, Defender's error log) look back `mde_linux_checks_history_hours`, 24 by default.
- Readiness checks, first in every run and alone in `mde_linux_checks_scope: preflight`: Microsoft's supported distributions, versions and architectures (carried as data, overridable), the kernel minimum, systemd, CPU, memory and Microsoft's 2 GB disk minimum, `noexec` on `/opt` or `/var`, fanotify permission events, BTF for eBPF, other blocking fanotify users, `iptables`, the clock.
- A device without the agent fails `agent_installed` only: every check that needs the agent is skipped, saying so, and the readiness checks still run.
- A read-only probe (`library/mde_linux_checks_probe.py`) that reads the host in one round trip, on Python 3.6 and later, so the checks run well through a bastion.
- Upgrade testing: a snapshot before the upgrade and the `upgrade_` checks after it (version, identity, settings, exclusions, health fields, definitions, dependencies, memory).
- Metrics for the report's limits (scan time, EICAR detection time, memory, CPU, reboot time and more), and evidence: what the probes read, and Microsoft's diagnostic package on failure.
- Unit tests on a real RHEL 9 host's probe data, and Molecule scenarios with the real package and a stub `mdatp` replaying captured output.
- `docs/estate-readiness.md` and `examples/estate-readiness.yml`: checking a whole estate's readiness before a rollout, and reading, parsing and comparing the results.
- `docs/using-without-galaxy.md`.
