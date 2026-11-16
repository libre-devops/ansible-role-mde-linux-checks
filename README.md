<div align="center">
  <a href="https://libredevops.org">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://libredevops.org/assets/libre-devops-white.png">
      <img alt="Libre DevOps" src="https://libredevops.org/assets/libre-devops-black.png" width="300">
    </picture>
  </a>
</div>

# Ansible Role: Defender for Endpoint on Linux checks

Tests Microsoft Defender for Endpoint on Linux: as a release test before a version goes to an estate, and as a health check of devices already running it. It covers readiness (can the host take Defender at all), installation, stability, protection, configuration, onboarding, the system, resource use and a reboot, and compares the host with how it was before an upgrade. Each of its 63 checks exists because something real goes wrong: many are named after the agent release that broke it.

It judges and records; it does not deploy. Install and configure the agent with [libre_devops.mde_linux](https://github.com/libre-devops/ansible-role-mde-linux), run these checks, then report on them with [libre_devops.test_results_report](https://github.com/libre-devops/ansible-role-test-results-report). The report is readable by people and parsable by pipelines, and judged against your thresholds.

[![CI](https://github.com/libre-devops/ansible-role-mde-linux-checks/actions/workflows/ci.yml/badge.svg)](https://github.com/libre-devops/ansible-role-mde-linux-checks/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/libre-devops/ansible-role-mde-linux-checks?sort=semver&label=release)](https://github.com/libre-devops/ansible-role-mde-linux-checks/releases/latest)
[![Galaxy](https://img.shields.io/badge/galaxy-libre__devops.mde__linux__checks-EE0000?logo=ansible&logoColor=white)](https://galaxy.ansible.com/ui/standalone/roles/libre_devops/mde_linux_checks/documentation/)
[![Licence](https://img.shields.io/github/license/libre-devops/ansible-role-mde-linux-checks)](./LICENSE)

---

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Profiles: release and health](#profiles-release-and-health)
- [Health checks of devices in use](#health-checks-of-devices-in-use)
- [Preflight: before an install or a rollout](#preflight-before-an-install-or-a-rollout)
- [The checks](#the-checks)
- [Online, offline and onboarded hosts](#online-offline-and-onboarded-hosts)
- [Testing an upgrade](#testing-an-upgrade)
- [Thresholds on what it measures](#thresholds-on-what-it-measures)
- [Evidence](#evidence)
- [How it works](#how-it-works)
- [Role variables](#role-variables)
- [What has been tested](#what-has-been-tested)
- [Troubleshooting](#troubleshooting)
- [Developing](#developing)
- [Releasing](#releasing)

## What it does

1. **Probes the host before anything happens**, and waits for the antivirus engine to load, so the end can be compared with the start. The readiness checks, which need no agent, come from this too (and are all that runs in the preflight scope).
2. **Acts on the host**, as the profile allows (nothing acts on a host without the agent):
   - updates security intelligence;
   - tests the connection to Defender's cloud;
   - writes the EICAR test file and times the detection;
   - runs a quick scan.

   A test that fails or runs out of time is recorded, never left to stop the play.
3. **Probes again**, sampling Defender's CPU and memory. It then **reboots** and probes once more, to prove the agent comes back by itself.
4. **Judges everything on the control node**, and leaves the results in `mde_linux_checks_test_results`, in the format `libre_devops.test_results_report` reads.
5. Optionally **saves a snapshot** before an upgrade, or **compares with one** after it, and keeps the **evidence**: what the probes read, plus Microsoft's diagnostic package when a check fails.

No check fails the play: every result reaches the report, and the report decides. The EICAR test file and its quarantined copy are removed afterwards, and so is the role's working directory.

## Requirements

| What | Detail |
|---|---|
| Control node | `ansible-core` 2.16 or later. |
| Managed nodes | Linux with systemd and mdatp installed. A Python your `ansible-core` supports: RHEL 8 and SLES 15 need [libre_devops.python](https://github.com/libre-devops/ansible-role-python) first. |
| Privileges | `become: true`: mdatp's health and threat history need root. |
| Network | None of its own. The online tests reach Microsoft's cloud from the host; set `mde_linux_checks_online: false` for hosts that cannot. Through a bastion everything works, the reboot included. |

## Installation

```bash
ansible-galaxy role install libre_devops.mde_linux_checks libre_devops.test_results_report
```

Or pin releases from GitHub, as in [`examples/requirements.yml`](./examples/requirements.yml). Without Galaxy, see [Using the role without Galaxy](./docs/using-without-galaxy.md). To check an estate before a rollout, see [Checking an estate's readiness](./docs/estate-readiness.md).

## Quick start

```yaml
- name: Test the Defender for Endpoint release
  hosts: release_test
  become: true
  vars:
    test_results_report_title: mdatp 101.26101.0000 release test
    test_results_report_dir: "{{ playbook_dir }}/artifacts/test-results"
  roles:
    - role: libre_devops.mde_linux
      vars:
        mde_linux_managed_config:
          antivirusEngine:
            enforcementLevel: real_time
    - role: libre_devops.mde_linux_checks
      vars:
        mde_linux_checks_expected_version: 101.26101.0000
    - role: libre_devops.test_results_report
```

Open `artifacts/test-results/test-results.md` first. The play fails if any check that counts failed.

## Profiles: release and health

| | `release` (default) | `health` |
|---|---|---|
| For | A release test on machines about to be thrown away | A health check of devices in use |
| Reads the host | Yes | Yes |
| Connectivity test (network only, changes nothing) | Yes, when online | Yes, when online |
| Security intelligence update (`mde_linux_checks_definitions_update`) | Yes, when online | Yes, when online |
| Quick scan (`mde_linux_checks_quick_scan`: load on the host for minutes) | Yes | Yes |
| EICAR test file (`mde_linux_checks_eicar`: raises an EICAR alert in the tenant when onboarded) | Yes | No |
| Reboot (`mde_linux_checks_reboot`) | Yes | No |

Every test is its own boolean, so either profile can be adjusted: `mde_linux_checks_quick_scan: false` on servers where the scan's load matters, or `mde_linux_checks_definitions_update: false` to leave updates to the agent's own schedule. A test left out is reported as skipped, with the reason.

## Health checks of devices in use

The same checks answer "is this device healthy?":

```yaml
- name: Check Defender is healthy across the estate
  hosts: linux_servers
  become: true
  roles:
    - role: libre_devops.mde_linux_checks
      vars:
        mde_linux_checks_profile: health
        mde_linux_checks_expected_org_id: 00000000-0000-0000-0000-000000000000
        mde_linux_checks_expected_enforcement_level: real_time
    - role: libre_devops.test_results_report
      vars:
        test_results_report_fail_severity: high      # only high and critical failures fail the run
        test_results_report_max_failed_hosts: 2      # all are in the report either way
```

The log-based checks look back `mde_linux_checks_history_hours` (24 by default), so they see what happened before the run, not only during it:
- `no_crashes`: core dumps and Defender crash files;
- `selinux_denials`;
- `journal_errors`;
- `error_log`.

`no_service_restarts` counts every automatic restart systemd has made since the service was last started.

**A device without the agent** fails `agent_installed` and nothing else. Every check that needs the agent is skipped with "Not checked: mdatp is not installed", and nothing acts on the host: no scan, no EICAR test file, no reboot. The checks that do not need the agent still run, as a readiness check:
- `system_requirements`;
- `disk_space_for_updates`, which becomes "There is room to install Defender";
- `filesystems_supported`;
- `time_synchronised`;
- `selinux_mode_unchanged`.

## Preflight: before an install or a rollout

`mde_linux_checks_scope: preflight` runs only the readiness checks: one probe, nothing acts on the host, and the agent does not have to be there. Run it across an estate before a rollout, to find the servers that cannot take Defender. Or run it at the start of a release pipeline, so an unsuitable test host stops the run before anything is installed:

```yaml
- name: Can these hosts take Defender for Endpoint?
  hosts: linux_servers
  become: true
  roles:
    - role: libre_devops.mde_linux_checks
      vars:
        mde_linux_checks_scope: preflight
    - role: libre_devops.test_results_report
      vars:
        test_results_report_title: Defender for Endpoint readiness
        test_results_report_max_failed_hosts: 1000   # report every host, fail none of the run
```

[Checking an estate's readiness](./docs/estate-readiness.md) is the full guide:
- running it across many hosts with [`examples/estate-readiness.yml`](./examples/estate-readiness.yml);
- reading the HTML report, and parsing the JSON or CSV into a work list;
- comparing runs as hosts are fixed.

Microsoft's support list changes with its releases. The role carries it as data (`vars/main.yml`, from the prerequisites page); replace it with `mde_linux_checks_supported_platforms` when Microsoft adds or drops a distribution before the role catches up.

## The checks

Every check has a stable id. Waivers, limits, expected checks and comparisons in the report select checks by it. A check that does not apply is **skipped with a reason**; one that could not get an answer is an **error**, never a pass. `mde_linux_checks_skip` turns any check off; it is reported as skipped.

### Readiness: can the host take Defender?

These need no agent, run first, and are the only checks in the preflight scope. On a host without the agent they still run, as a readiness check.

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `supported_platform` | High | The distribution, version and architecture are on Microsoft's support list (`/etc/os-release` against `mde_linux_checks_supported_platforms`). | The list has traps: Ubuntu LTS only, Rocky 8.7+ and 9.2+, Alma 8.4+ and 9.2+, SLES on ARM64 only 15 SP5, SP6 and 16, Amazon Linux 2 on ARM64 ended 31 October 2026. Others may run as a custom OS, outside Microsoft's support. |
| `kernel_supported` | Critical | The kernel is 3.10.0-327 or later. | Microsoft's minimum for every distribution. |
| `systemd_present` | Critical | systemd is PID 1. | Defender's service needs it. |
| `system_requirements` | High | At least 1 CPU and 1 GiB of memory (870 MiB after the kernel's share). | Microsoft's minimum. |
| `disk_space_for_updates` | High | With the agent: `/opt` has room for the next platform update (1.2 times the install) and `/var` for a security intelligence update (twice Defender's data). Without it: Microsoft's 2 GB minimum across `/opt` and `/var` (counted once when they share a file system), with at least 600 MiB in `/opt` and 400 MiB in `/var`. | An update unpacks beside the old version first. On the Azure RHEL 9 image the 432 MiB install left 1.48 GiB free on `/opt`. |
| `mounts_allow_exec` | Critical | `/opt` and `/var` are not mounted `noexec`. | The agent runs from `/opt/microsoft/mdatp`, and its engine updates into `/var/opt/microsoft/mdatp`. Hardening baselines set `noexec` on `/tmp` and `/var/tmp`; set on `/opt` or `/var` it stops the agent. |
| `filesystems_supported` | Medium | `/`, `/opt`, `/var`, `/tmp` and `/home` are on file systems real-time protection watches. | NFS or CIFS home directories are not protected in real time. |
| `fanotify_supported` | High | The running kernel has `CONFIG_FANOTIFY` and `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`. | Real-time protection blocks files through fanotify permission events. Skipped when the kernel's config is not readable. |
| `ebpf_supported` | Medium | The kernel has BTF (`/sys/kernel/btf/vmlinux`). | Without it EDR falls back to the netlink provider and sees less. |
| `fanotify_conflicts` | High | No other process uses fanotify in blocking mode, from `/proc/<pid>/fdinfo`. fapolicyd passes on RHEL and Fedora, where Microsoft supports it. | Microsoft warns another blocking fanotify product can hang the system. mdatp reports this only once installed (`conflicting_applications`). |
| `iptables_present` | Low | `iptables` is installed. | The package needs it and device isolation uses it. dnf and apt bring it, but an install from package files must push it too. |
| `time_synchronised` | Medium | The clock is NTP-synchronised. | Certificate checks against the cloud fail when it drifts. |

### Installation

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `agent_installed` | Critical | One mdatp package is installed and the `mdatp` command exists. | An interrupted upgrade can leave two versions installed. |
| `agent_version` | Critical | The installed version is `mde_linux_checks_expected_version`. | That the release under test is the one installed. Skipped without an expected version. |
| `package_signature` | High | The RPM is signed with one of Microsoft's keys (`be1229cf`, `f748182b`). | Supply chain: a rebuilt or tampered package fails. Skipped on Debian, whose packages keep no signature once installed. |
| `package_dependencies` | High | `rpm -V --nofiles` (or `dpkg --audit`) finds nothing missing. | Installs from package files can lack dependencies. |
| `package_files_intact` | Medium | No package file differs from the package, configuration files apart. | Hardening tools and hand edits break the agent. |
| `health_readable` | Critical | `mdatp health` answers, in how many milliseconds. | Everything else reads it. |

### Stability

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `service_running` | Critical | The `mdatp` unit is active and running. | |
| `service_enabled` | Critical | It starts at boot. | Versions 101.26042.0000 to 0009 could leave it disabled after an upgrade and reboot. |
| `no_service_restarts` | High | systemd has not restarted it since it was last started, and its main process did not change during the checks. | 101.26072.0004 could restart `wdavdaemon` while scanning processes. |
| `no_crashes` | High | No core dump or Defender crash file in the last `mde_linux_checks_history_hours`. | |
| `no_unexpected_reboot` | Critical | The boot id did not change (before the deliberate reboot). | 101.25102.0005 fixed real-time scanning of `/dev/watchdog` rebooting hosts. |
| `error_log` | Info | Defender logged nothing fatal or critical in the look-back window; counts its errors and warnings as metrics. | A device that is not onboarded logs errors all the time, so errors alone are only measured. |
| `journal_errors` | Low | The unit logged no error-priority journal entries in the look-back window. | |
| `service_survives_reboot` | Critical | After a reboot the service is running and enabled, the engine loads, real-time protection is available, and no new health issue appeared. Times how long until the host answers. | The 101.26042 upgrade fault showed only after a reboot. Skipped by the health profile. |

### Protection

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `engine_loaded` | Critical | The antivirus engine loaded, and how long it took. | From 101.26062.0007 an engine that fails signature verification is not loaded. |
| `enforcement_level` | High | The antivirus runs at `mde_linux_checks_expected_enforcement_level`, and whether it is `[managed]`. | The default is passive, which protects nothing in real time. Read from `antivirus_enforcement_level` (101.26052.0012 and later), or worked out from older versions' fields. |
| `real_time_protection` | Critical | Real-time protection is enabled and available. | Skipped at passive or on-demand, where it is off by design. |
| `real_time_subsystem` | Medium | It has a working subsystem (fanotify), not `unavailable`. | |
| `supplementary_events` | High | EDR events come from eBPF. The netlink fallback fails at medium severity; auditd, unsupported from 101.24082.0004, fails at high. | Kernels without eBPF support give EDR less to see. |
| `conflicting_applications` | High | No other fanotify-based security product runs in blocking mode. | Microsoft warns they can hang the system. |
| `offline_cloud_protection` | High | On a host marked offline, cloud-delivered protection is off. | With it on and no route to Microsoft, every lookup waits for the cloud to time out: on a RHEL 9 VM with no internet the EICAR detection took 40.5 s, and 0.4 s with it off. Skipped online. |
| `engine_signature_verification` | Medium | The engine's signature is checked before it loads. | Default from 101.26062.0007; skipped on older versions. |
| `folder_permissions` | High | `mdatp health --details permissions` finds no issue. | CIS-style hardening of `/var/opt/microsoft` or `/var/log/microsoft` breaks the agent. |
| `eicar_detection` | Critical | The EICAR test file is detected: removed at `real_time`, reported at `audit`, found by a custom scan at passive or on-demand. Times the detection. | It is the proof that the antivirus works, not just that it is configured. |
| `quick_scan` | High | `mdatp scan quick` completes, with its time and the files scanned. A scan that runs out of time is cancelled. | 101.26062.0007 fixed scans that hung. mdatp runs on-demand scans only on an onboarded device, so it is skipped otherwise. |
| `definitions_update` | High | Security intelligence updates from Microsoft. | Skipped offline, or with `mde_linux_checks_definitions_update: false`. |
| `definitions_current` | High | Definitions are `up_to_date` and no older than `mde_linux_checks_max_definitions_age_hours`. | Skipped offline, naming the version the package shipped. |
| `product_expiry` | High | The version has at least `mde_linux_checks_min_days_to_expiry` days before it expires. | Each version expires nine months after release. mdatp reports the date only once onboarded. |

### Configuration

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `managed_config_valid` | High; critical when broken | `mdatp_managed.json` is valid JSON. | mdatp ignores an invalid file completely, so every setting reverts to its default. |
| `managed_config_applied` | High | The settings in the file show as `[managed]` in `mdatp health`. | The documented way to prove the agent took the file up. |
| `health.<field>` | High | Each field in `mde_linux_checks_expected_health` has the value (or one of the values) given. | Your policy: `{cloud_enabled: true, network_protection_enforcement_level: [audit, block]}`. |

### Onboarding

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `onboarded` | Critical | The device is licensed. | Expected when an onboarding package is on the host, or set with `mde_linux_checks_onboarded`. |
| `organisation` | Critical | It is onboarded to `mde_linux_checks_expected_org_id`. | A package for the wrong tenant onboards happily. |
| `healthy` | Critical | Defender reports itself healthy. | Skipped when not onboarded: such a device is never healthy. |
| `health_issues` | High | Defender lists no health issues. `missing license` is accepted on a device not meant to be onboarded. | |
| `edr_identity` | High | The device has an `edr_machine_id`. | |
| `unique_identity` | Critical | No other host in the run shares its `machine_guid` or `edr_machine_id`. | VMs cloned from an image with Defender installed share identities and show as one device. 101.25072.0003, 101.25092.0002 and 101.26081.0010 fixed cases of it. |
| `cloud_connectivity` | High | `mdatp connectivity test` reaches every URL, with how many and how long. | 101.25122.0004 added a URL that firewalls must allow. Skipped offline. |

### The system

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `selinux_policy` | Medium | A Defender SELinux module is loaded. | 101.26032.0000 fixed upgrades removing its SELinux modules. Skipped without SELinux. |
| `selinux_denials` | High | SELinux denied Defender's processes nothing in the look-back window. | Catches install-time denials too. |
| `selinux_mode_unchanged` | High | The SELinux mode did not change during the checks. | |

### Resources

| Id | Severity | Proves | Why it is here |
|---|---|---|---|
| `resource_usage` | Medium | Measures Defender's processes: resident memory (`memory_mib`) and CPU over `mde_linux_checks_sample_seconds` (`cpu_percent`). | To limit and compare releases with the report's limits. |
| `disk_usage` | Info | Measures the install, data and log directories. | |

### Upgrade (when comparing with a snapshot)

| Id | Severity | Proves |
|---|---|---|
| `upgrade_compared` | High | A snapshot from before the upgrade was compared. Skipped without one, an error when the file is missing. |
| `upgrade_version` | Critical | A newer version is installed than in the snapshot. The same version, or a downgrade, fails. |
| `upgrade_identity` | Critical | `machine_guid`, `edr_machine_id` and `org_id` are unchanged. A new identity shows as a second device in the portal. |
| `upgrade_settings` | High | Each of `mde_linux_checks_preserved_fields` is unchanged, and still `[managed]` if it was. |
| `upgrade_exclusions` | High | The antivirus exclusions are unchanged. |
| `upgrade_health_fields` | Medium | `mdatp health` still reports every field it did; new fields are listed. Scripts and monitoring that read a removed field break. |
| `upgrade_definitions` | Medium | Security intelligence was not rolled back. |
| `upgrade_dependencies` | Info | The package needs no new dependencies; new ones are listed. Hosts without repositories (offline, or a Satellite content view) need them too. |
| `upgrade_resources` | Info | Memory before and after, as `memory_change_percent`, for a limit. |

## Online, offline and onboarded hosts

What runs depends on what the host can reach and whether it is onboarded. Nothing that cannot work there is failed; it is skipped with the reason.

| Checks | Online and onboarded | Online, not onboarded | Offline, not onboarded |
|---|---|---|---|
| Installation, stability, system, resources, reboot | Run | Run | Run |
| Real-time protection and the EICAR test (at `real_time` or `audit`) | Run | Run | Run |
| `quick_scan`, EICAR by custom scan | Run | Skipped: mdatp scans on demand only when onboarded | Skipped |
| `definitions_update`, `definitions_current`, `cloud_connectivity` | Run | Run | Skipped |
| `onboarded`, `organisation`, `healthy`, `product_expiry` | Run | Skipped | Skipped |
| `offline_cloud_protection` | Skipped | Skipped | Run |

`mde_linux_checks_online: false` marks an offline host. Onboarding is worked out from the host unless `mde_linux_checks_onboarded` says otherwise.

## Testing an upgrade

Snapshot the host on the version your estate runs, upgrade it, and compare:

```yaml
- name: Before the upgrade
  hosts: release_test
  become: true
  roles:
    - role: libre_devops.mde_linux
      vars:
        mde_linux_version: 101.26091.0004
    - role: libre_devops.mde_linux_checks
      vars:
        mde_linux_checks_profile: health
        mde_linux_checks_quick_scan: false
        mde_linux_checks_snapshot_to: "{{ playbook_dir }}/snapshots/{{ inventory_hostname }}.json"
    - role: libre_devops.test_results_report
      vars:
        test_results_report_dir: "{{ playbook_dir }}/artifacts/before"

- name: After the upgrade
  hosts: release_test
  become: true
  roles:
    - role: libre_devops.mde_linux
      vars:
        mde_linux_version: 101.26101.0000
    - role: libre_devops.mde_linux_checks
      vars:
        mde_linux_checks_expected_version: 101.26101.0000
        mde_linux_checks_compare_to: "{{ playbook_dir }}/snapshots/{{ inventory_hostname }}.json"
    - role: libre_devops.test_results_report
      vars:
        test_results_report_dir: "{{ playbook_dir }}/artifacts/after"
        test_results_report_compare_to: "{{ playbook_dir }}/artifacts/before/test-results.json"
```

The second report has the `upgrade_` checks, and also lists what regressed since the first.

## Thresholds on what it measures

The checks report numbers as metrics. Limits on them belong in the report, so one policy covers every run:

```yaml
test_results_report_limits:
  - check: quick_scan
    metric: duration_seconds
    max: 900
  - check: eicar_detection
    metric: detection_seconds
    max: 10
  - check: resource_usage
    metric: memory_mib
    max: 1024
  - check: resource_usage
    metric: cpu_percent
    max: 5
  - check: upgrade_resources
    metric: memory_change_percent
    max: 25
    severity: medium
  - check: service_survives_reboot
    metric: seconds_until_reachable
    max: 300
```

| Check | Metrics |
|---|---|
| `health_readable` | `health_seconds`, `health_fields` |
| `engine_loaded` | `seconds_to_load` |
| `no_service_restarts`, `no_crashes` | `restarts`, `crashes` |
| `error_log`, `journal_errors` | `errors`, `warnings`, `fatal`, `entries` |
| `eicar_detection` | `detection_seconds` |
| `quick_scan` | `duration_seconds`, `files_scanned`, `threats` |
| `definitions_update`, `definitions_current` | `duration_seconds`, `age_hours` |
| `product_expiry` | `days_to_expiry` |
| `cloud_connectivity` | `urls_tested`, `urls_failed`, `duration_seconds` |
| `system_requirements` | `cpus`, `memory_total_mib` |
| `disk_space_for_updates` | `free_opt_mib`, `free_var_mib`, `install_mib`, `data_mib` |
| `selinux_denials` | `denials` |
| `resource_usage` | `memory_mib`, `cpu_percent`, `processes` |
| `disk_usage` | `install_mib`, `data_mib`, `logs_mib` |
| `service_survives_reboot` | `seconds_until_reachable`, `seconds_to_load_after_reboot` |
| `upgrade_health_fields`, `upgrade_resources` | `fields_removed`, `fields_added`, `memory_mib_before`, `memory_mib`, `memory_change_percent` |

The suite's properties record what was tested on each host: the app, engine and definitions versions, the package, the release ring, the enforcement level, whether it is onboarded, the event provider, the kernel, SELinux and FIPS mode, the profile.

## Evidence

Set `mde_linux_checks_evidence_dir` and each host gets a directory on the control node:

| File | What |
|---|---|
| `probes.json` | Everything the probes read before, after and after the reboot, and what each test did and printed. |
| `mdatp-health.txt` | `mdatp health` as the agent printed it. |
| `mdatp-diagnostic.zip` | Microsoft's diagnostic package (`mdatp diagnostic create`), when a check failed (`on_failure`, the default), `always`, or `never`. It is what Microsoft support asks for. |

## How it works

- **Read, then judge.** A probe module (`library/mde_linux_checks_probe.py`) reads everything in one round trip:
  - the agent: health and its detail sections, the threat history and the exclusions;
  - the package and the service;
  - the processes' memory and CPU;
  - the system: the boot id, file systems and free space, SELinux, FIPS and the clock;
  - what happened since the checks started: logs, SELinux denials, crash dumps.

  It changes nothing, and runs on Python 3.6 and later. The judgement is a filter on the control node (`filter_plugins/mde_linux_checks.py`), unit-tested on real probe data. Through a bastion, where every task is a round trip, the whole run takes about four minutes, the reboot included.
- **Documented fields only.** The checks read `mdatp health`'s text output, whose field names Microsoft documents, not its JSON, whose names are not documented. A field a version lacks makes its check skip rather than fail, so the role works across releases.
- **The EICAR test** (`library/mde_linux_checks_eicar.py`) assembles the test string from two halves, so no file in this repository holds it whole. It waits for the detection the enforcement level promises, then removes the file and its quarantined copy.

## Role variables

Every variable is validated against [`meta/argument_specs.yml`](./meta/argument_specs.yml) when the role starts. Defaults are in [`defaults/main.yml`](./defaults/main.yml).

| Variable | Default | Description |
|---|---|---|
| `mde_linux_checks_profile` | `release` | `release` adds the EICAR test and a reboot; `health` leaves them out. See [Profiles](#profiles-release-and-health). |
| `mde_linux_checks_scope` | `full` | `full` runs every check, readiness first; `preflight` runs only the readiness checks. See [Preflight](#preflight-before-an-install-or-a-rollout). |
| `mde_linux_checks_supported_platforms` | Microsoft's list | The supported distributions, by `/etc/os-release` ID, architecture and versions (`"9"` any 9.x, `"8.7+"` 8.7 and later 8.x, `"24.04"` that release). |
| `mde_linux_checks_online` | `true` | Whether the host can reach Microsoft's cloud. |
| `mde_linux_checks_onboarded` | `auto` | Whether the device should be onboarded: `auto`, `true` or `false`. |
| `mde_linux_checks_expected_version` | `""` | The version that should be installed. |
| `mde_linux_checks_expected_org_id` | `""` | The organisation it should be onboarded to. |
| `mde_linux_checks_expected_enforcement_level` | `real_time` | `real_time`, `audit`, `on_demand`, `passive`, or empty to skip. |
| `mde_linux_checks_expected_health` | `{}` | Health fields and the values they must have. |
| `mde_linux_checks_skip` | `[]` | Check ids to skip. |
| `mde_linux_checks_eicar` | `true` for release | Run the EICAR test. |
| `mde_linux_checks_quick_scan` | `true` | Run a quick scan. |
| `mde_linux_checks_definitions_update` | `true` when online | Update security intelligence. |
| `mde_linux_checks_connectivity_test` | `true` when online | Run `mdatp connectivity test`. |
| `mde_linux_checks_reboot` | `true` for release | Reboot and check Defender comes back. |
| `mde_linux_checks_history_hours` | `24` | How far back the log-based checks look. `0` looks only at the run. |
| `mde_linux_checks_min_days_to_expiry` | `30` | Fewest days before the version expires. |
| `mde_linux_checks_max_definitions_age_hours` | `48` | Oldest security intelligence allowed online. |
| `mde_linux_checks_engine_timeout` | `300` | Seconds to wait for the engine, before the checks and after the reboot. |
| `mde_linux_checks_eicar_timeout` | `120` | Seconds to wait for the EICAR detection. |
| `mde_linux_checks_scan_timeout` | `1800` | Seconds before the quick scan is cancelled. |
| `mde_linux_checks_definitions_timeout` | `600` | Seconds for the security intelligence update. |
| `mde_linux_checks_connectivity_timeout` | `600` | Seconds for the connectivity test. |
| `mde_linux_checks_reboot_timeout` | `900` | Seconds for the host to come back. |
| `mde_linux_checks_sample_seconds` | `30` | Seconds to sample Defender's CPU use. |
| `mde_linux_checks_work_dir` | `/var/tmp/mde-linux-checks` | The tests' directory on the host, removed afterwards. It must be on a file system real-time protection watches. |
| `mde_linux_checks_snapshot_to` | `""` | Control node file to save a snapshot to, before an upgrade. |
| `mde_linux_checks_compare_to` | `""` | Snapshot to compare with, after an upgrade. |
| `mde_linux_checks_preserved_fields` | 13 protection settings | Health fields an upgrade must not change. |
| `mde_linux_checks_evidence_dir` | `""` | Control node directory for the evidence. |
| `mde_linux_checks_collect_diagnostics` | `on_failure` | When to collect Microsoft's diagnostic package: `on_failure`, `always`, `never`. |

| Fact | What it holds |
|---|---|
| `mde_linux_checks_test_results` | The suite: `suite: mde_linux_checks`, the properties and every check, in the format `libre_devops.test_results/v1`. |

## What has been tested

- **Live, 15 November 2026, on a RHEL 9.8 Azure VM** (2 vCPUs, 4 GiB), reached through Azure Bastion. mdatp 101.26101.0000, real-time protection on, online, not onboarded:
  - every check that can run on a host that is not onboarded passed, and the eight that cannot were skipped with the reasons above;
  - EICAR was detected in 0.4 s;
  - the reboot was back in about 150 s;
  - the run took 3 minutes 40 seconds.
- **The same VM, upgraded** from 101.26091.0004 to 101.26101.0000: every `upgrade_` check passed, and memory fell 10.9%.
- **Live, 15 November 2026, on a RHEL 9.8 Azure VM with no route out** (the azure-orchestration `mde-rhel-offline` stack): mdatp 101.26101.0000 installed from the RPM through the bastion, then the checks with `mde_linux_checks_online: false`. Every check that can run offline passed, and the run took 5 minutes 32 seconds with the install. It found that cloud-delivered protection, on by default, made every detection wait for the cloud: EICAR in 40.5 s, against 0.4 s with `cloudService.enabled: false`. Hence `offline_cloud_protection`.
- **In CI**, Molecule installs the real mdatp package with `libre_devops.mde_linux` in systemd containers on RHEL 9, Debian 12 and Ubuntu 24.04. A stub `mdatp` command replays the VM's output, or a broken version of it. The package, service, process and system probes are real.
- **Unit tests** cover every check on the VM's probe data, and on that data changed to break each one.
- **Not yet tested:**
  - an onboarded device: `quick_scan`, `healthy`, `organisation` and `product_expiry`, whose formats follow Microsoft's documentation;
  - Debian and Ubuntu outside containers;
  - SLES, and RHEL 8.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `quick_scan` skipped: "runs on-demand scans only on an onboarded device" | Expected before onboarding: mdatp answers `No scan is running`. |
| `eicar_detection` failed at `real_time` | `real_time_protection` and `folder_permissions`, and exclusions covering `mde_linux_checks_work_dir`. |
| `enforcement_level` failed: passive | The default without `mdatp_managed.json`. Set `antivirusEngine.enforcementLevel`, or the level your estate runs in `mde_linux_checks_expected_enforcement_level`. |
| `disk_space_for_updates` failed | The next update needs the room shown. On Azure RHEL images `/opt` is small: grow it or mount `/opt` separately. |
| `service_survives_reboot` is an error | The host did not come back within `mde_linux_checks_reboot_timeout`. Through a bastion, check the tunnel is still open. |
| `upgrade_compared` is an error | Take the snapshot (`mde_linux_checks_snapshot_to`) before the upgrade, and give the same path to `mde_linux_checks_compare_to` after it. |

## Developing

You need [uv](https://docs.astral.sh/uv/), [just](https://github.com/casey/just) and [podman](https://podman.io/). CI runs the same recipes.

| Recipe | What it does |
|---|---|
| `just deps` | Installs the pinned Python tools (`uv.lock`) and the test collections into `.ansible/`. |
| `just lint` | `yamllint`, `ansible-lint` on the production profile, `ruff` and `zizmor`. |
| `just unit` | The unit tests: every check, the probe's parsers, and the results against the report's format. |
| `just test [scenario] [platform]` | A Molecule scenario: `default` (the real host's output), `failures` (broken output) or `no_agent` (preflight, and a full run with no agent). `just test default rhel9`. |
| `just converge <scenario> <platform>` | Runs a scenario and leaves the container, pass or fail. `just login` opens a shell in it. |
| `just live <inventory> [args]` | Runs [`examples/playbook.yml`](./examples/playbook.yml) against real hosts. |

New fixtures come from real hosts. Capture what `molecule/resources/mdatp-stub.py` answers with, replace device ids with made-up ones, and say in `molecule/fixtures/README.md` where they came from.

## Releasing

1. Move the Unreleased entries in [`CHANGELOG.md`](./CHANGELOG.md) under the new version.
2. Run `just release 1.2.3`. It tags the commit and pushes the tag.
3. The Release workflow creates the GitHub release, imports the tag into Galaxy and installs it back from Galaxy to check. It needs the `GALAXY_API_KEY` secret from the libre-devops organisation. The import uses Galaxy's API through [`scripts/galaxy-import.py`](./scripts/galaxy-import.py), because Galaxy namespaces cannot contain a hyphen.

## Licence

[MIT](./LICENSE).
