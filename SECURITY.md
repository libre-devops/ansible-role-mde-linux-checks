# Security policy

## Reporting a vulnerability

Report vulnerabilities in this role privately, through [GitHub's private vulnerability reporting](https://github.com/libre-devops/ansible-role-mde-linux-checks/security/advisories/new). Do not open a public issue.

## What the role does to a host

| Test | Effect | Profile |
|---|---|---|
| Probes | Read only: mdatp's health, threat history and exclusions, the package database, systemd, `/proc`, the audit log and the journal. | Both |
| Connectivity test | Network connections from the host to Microsoft's endpoints. | Both, when online |
| EICAR test file | Writes the industry's harmless antivirus test string to `mde_linux_checks_work_dir`, then removes the file and its quarantined copy. On an onboarded device this raises an EICAR alert in the tenant, which is expected. | release |
| Quick scan | Load on the host while it runs. | release |
| Security intelligence update | Downloads definitions from Microsoft. | release |
| Reboot | Reboots the host. | release |

Use the `audit` profile on servers in use. The EICAR string is assembled from two halves at run time, so no file in this repository holds it whole.

## What the results hold

The results and the evidence directory hold what the probes read: versions, device identifiers (`machine_guid`, `edr_machine_id`, `org_id`), health issues, log excerpts and, on failure, Microsoft's diagnostic package. Keep them where the hosts' details may go.
