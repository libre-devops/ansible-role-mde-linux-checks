# Checking an estate's readiness for Defender for Endpoint

Before a rollout of Microsoft Defender for Endpoint on Linux, find out which servers can take it, which cannot, and why. The readiness checks in this role do that across any number of hosts:
- one read-only probe per host;
- no agent needed, and nothing installed or changed;
- the results in a report a person can read and a pipeline can parse.

The same playbook, run again after fixes, shows what changed.

## Contents

- [What it checks](#what-it-checks)
- [What it cannot tell you](#what-it-cannot-tell-you)
- [What you need](#what-you-need)
- [Running it](#running-it)
- [Reading the results](#reading-the-results)
- [Parsing the results](#parsing-the-results)
- [Your own report](#your-own-report)
- [Running it again](#running-it-again)
- [Hosts that already run Defender](#hosts-that-already-run-defender)
- [Keeping the support list current](#keeping-the-support-list-current)

## What it checks

Microsoft's prerequisites, and the things that stop an install or the agent working. The README's [readiness table](../README.md#readiness-can-the-host-take-defender) has the detail.

| Check | Fails when |
|---|---|
| `supported_platform` | The distribution, version or architecture is not on Microsoft's support list. Ubuntu non-LTS releases, Rocky before 8.7 or 9.2, Alma before 8.4 or 9.2, and Amazon Linux 2 on ARM64 are the usual surprises. |
| `kernel_supported` | The kernel is older than 3.10.0-327. |
| `systemd_present` | systemd is not PID 1. |
| `system_requirements` | Fewer than 1 CPU or 1 GiB of memory. |
| `disk_space_for_updates` | Less than Microsoft's 2 GB free across `/opt` and `/var`, or less than 600 MiB in `/opt` or 400 MiB in `/var`. |
| `mounts_allow_exec` | `/opt` or `/var` is mounted `noexec`, which hardening baselines sometimes do. |
| `filesystems_supported` | `/`, `/opt`, `/var`, `/tmp` or `/home` is on a file system real-time protection does not watch, such as NFS. |
| `fanotify_supported` | The kernel lacks fanotify permission events, which real-time protection blocks files with. |
| `ebpf_supported` | The kernel has no BTF, so EDR would fall back to the netlink provider. |
| `fanotify_conflicts` | Another product uses fanotify in blocking mode, which Microsoft warns can hang the system. fapolicyd on RHEL and Fedora is supported. |
| `iptables_present` | `iptables` is missing: dnf and apt install it with the agent, but an install from package files must bring it. |
| `time_synchronised` | The clock is not NTP-synchronised. |

## What it cannot tell you

- **Whether the host can reach Defender's cloud.** `mdatp connectivity test` needs the agent. Check the [streamlined connectivity URLs](https://learn.microsoft.com/en-us/defender-endpoint/streamlined-device-connectivity-urls-commercial) through your firewall and proxy separately. Hosts that never will reach them need `cloudService.enabled: false`, or every detection waits for the cloud: on a test VM with no route out, the EICAR test took 40 s instead of 0.4 s.
- **Licensing**, and whether your change process allows the rollout.
- **How the agent behaves under the host's workload.** Pilot on a few hosts of each kind, and run the [full checks](#hosts-that-already-run-defender) there.

## What you need

| What | Detail |
|---|---|
| Control node | `ansible-core` 2.16 or later, and the roles: `ansible-galaxy role install libre_devops.mde_linux_checks libre_devops.test_results_report`. |
| Access | SSH and `become`. Root is needed to see other processes' fanotify use and, on some distributions, the kernel's configuration; without it those checks are skipped, never passed. |
| Managed nodes | A Python your `ansible-core` supports. RHEL 8 and SLES 15 ship Python 3.6: see [libre_devops.python](https://github.com/libre-devops/ansible-role-python), or run ansible-core 2.16 for them. |

## Running it

[`examples/estate-readiness.yml`](../examples/estate-readiness.yml) is ready to use:

```bash
ansible-playbook -i inventory.ini examples/estate-readiness.yml -f 50
```

Or, for one group:

```bash
ansible-playbook -i inventory.ini examples/estate-readiness.yml -e readiness_hosts=rhel_servers
```

It runs the checks with `mde_linux_checks_scope: preflight` and writes the report to `readiness/<date and time>/`. Each host takes seconds, so `-f` (forks) sets the pace for a large estate. A host that cannot be reached is in the report as **No results**, so the report accounts for every host in the inventory.

It reports rather than fails, by these settings:

| Setting | Why |
|---|---|
| `test_results_report_enforce: false` | A host that cannot take Defender is a finding, not a failed run. |
| `test_results_report_fail_severity: medium` | `iptables_present` (low) is a note: hosts with repositories get it with the agent. |
| `test_results_report_formats: [json, html, csv]` | The page to read, the data to parse, and a spreadsheet. |

Any of the [report's settings](https://github.com/libre-devops/ansible-role-test-results-report#role-variables) can change that. Use `test_results_report_waivers` to accept a known gap, with a reason and an expiry date, so it stays visible without counting. For example, NFS home directories you will not protect in real time.

## Reading the results

Open `readiness/<date and time>/test-results.html`. It is one self-contained file, so it can also be emailed or attached to the change record. It shows:
- how many hosts are ready, and why the others are not;
- a table of hosts, and every problem ordered by severity, each with what was found and what to do;
- every result.

Every table filters as you type, sorts by any column, and copies as CSV. Type `Failed`, or a check id such as `mounts_allow_exec`, to see just those.

`test-results.csv` has one row per host and check. In a spreadsheet, a pivot on `id` and `outcome` shows how many hosts each problem affects.

## Parsing the results

`test-results.json` is the whole report, in a [published format](https://github.com/libre-devops/ansible-role-test-results-report/blob/main/files/schemas/test-results-report.schema.json): flat `hosts` and `results` tables, every key always present. Some `jq`:

```bash
r=readiness/20261116-090000/test-results.json

# The hosts that can take Defender.
jq -r '.hosts[] | select(.verdict == "passed") | .host' "$r"

# What stops the rest, one line per problem.
jq -r '.results[] | select(.outcome == "failed" or .outcome == "error") | [.host, .severity, .id, .detail] | @tsv' "$r"

# How many hosts each problem affects, worst first: the rollout's work list.
jq -r '[.results[] | select(.outcome == "failed" or .outcome == "error")] | group_by(.id)
       | map({check: .[0].id, hosts: (map(.host) | unique | length)}) | sort_by(-.hosts)[] | "\(.hosts)\t\(.check)"' "$r"

# The unsupported distributions, counted.
jq -r '.results[] | select(.id == "supported_platform" and .outcome != "passed") | .detail' "$r" | sort | uniq -c

# One line per host, for a change record or a CMDB.
jq -r '["host", "ready", "problems"],
       (.hosts[] as $h | [$h.host, ($h.verdict == "passed"),
         ([.results[] | select(.host == $h.host and (.outcome == "failed" or .outcome == "error")) | .id] | join(" "))])
       | @csv' "$r"
```

PowerShell reads it as well:

```powershell
$report = Get-Content readiness/20261116-090000/test-results.json -Raw | ConvertFrom-Json
$report.results | Where-Object outcome -in 'failed', 'error' | Group-Object id | Sort-Object Count -Descending | Select-Object Count, Name
```

## Your own report

The JSON is a contract, so build what you need from it rather than scraping the page: a management summary, a ticket per blocking problem, a CMDB field.

For the page itself, copy the report role's [HTML template](https://github.com/libre-devops/ansible-role-test-results-report/blob/main/templates/test-results.html.j2) and set `test_results_report_html_template` to your copy. It renders the same data, with every value escaped.

## Running it again

Keep each run's directory. After fixing hosts, run again with the previous report to compare:

```bash
ansible-playbook -i inventory.ini examples/estate-readiness.yml \
  -e test_results_report_compare_to=$PWD/readiness/20261116-090000/test-results.json
```

The new report lists what was fixed, what regressed and what no longer reports. Hosts are matched by their label, which is the inventory name unless you set `test_results_report_host_label`.

## Hosts that already run Defender

The full checks, in the `health` profile, answer "is it healthy?" on hosts already running the agent. They read health, protection, configuration, onboarding and stability, and the readiness checks still come first. They run no EICAR test and no reboot:

```yaml
- role: libre_devops.mde_linux_checks
  vars:
    mde_linux_checks_profile: health
    mde_linux_checks_quick_scan: false       # leave scans to the schedule on busy servers
```

A host without the agent fails `agent_installed` alone and still gets the readiness checks, so one run covers a mixed estate.

## Keeping the support list current

Microsoft changes its supported distributions with its releases. The role carries the list as data, in [`vars/main.yml`](../vars/main.yml), taken from the [prerequisites page](https://learn.microsoft.com/en-us/defender-endpoint/mde-linux-prerequisites). When Microsoft changes it before the role catches up, set `mde_linux_checks_supported_platforms`, for example in `group_vars/all.yml`:

```yaml
mde_linux_checks_supported_platforms:
  rhel:
    x86_64: ["7.2+", "8", "9", "10"]
    aarch64: ["8", "9", "10"]
  ubuntu:
    x86_64: ["20.04", "22.04", "24.04", "26.04"]
    aarch64: ["22.04", "24.04", "26.04"]
```

It replaces the whole list, so include every distribution you run. A version is `"9"` (any 9.x), `"8.7+"` (8.7 and later 8.x) or `"24.04"` (that release only).
