# Changelog

Notable changes to this role. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Fixed

- After a reboot the probe waited for the antivirus engine only, so on a fast-booting host `service_survives_reboot` could read real-time protection and the event providers while they were still starting, and fail. Found live on RHEL 8.10, probed 22 s after boot. The wait (`mde_linux_checks_engine_timeout`) now also holds until real-time protection is available, when it is enabled, and the supplementary event provider is up, before the checks as well as after the reboot. The new metric `seconds_to_protect_after_reboot` keeps how long that took, so a slow start still shows.

## 1.1.0 - 2026-11-16

### Added

- RHEL 7. `ebpf_supported` now uses Microsoft's minimum kernel for the eBPF provider on each distribution (RHEL and CentOS 7.6 and later: 3.10.0-957.10), and looks for BTF only off that table: RHEL 7 has no BTF but is supported. The probe reads `timedatectl status` where `timedatectl show` is missing (systemd before 239, such as RHEL 7's 219). `no_service_restarts` says when systemd does not count restarts (before 235). CI runs `no_agent` on UBI 7.
- Diagrams: a Mermaid flowchart of a run in the README, and `docs/diagrams/mde-linux-checks.drawio` with three pages (a run, the 63 checks by group, testing an upgrade).

## 1.0.1 - 2026-11-16

### Fixed

- The Galaxy description fits Galaxy's 255-character limit. Galaxy refused 1.0.0 for it, so 1.0.1 is the first release on Galaxy; 1.0.0 is on GitHub only. `just lint` now checks the length.

## 1.0.0 - 2026-11-16

### Added

- First release.
- Checks of Microsoft Defender for Endpoint on Linux in nine groups: readiness, installation, stability, protection, configuration, onboarding, the system, resources and upgrade, each with a stable id and a severity, left in `mde_linux_checks_test_results` in the format `libre_devops.test_results_report` reads.
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
