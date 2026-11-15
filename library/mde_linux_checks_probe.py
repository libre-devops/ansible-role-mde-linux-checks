#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Craig Thacker (Libre DevOps). MIT licence: see LICENSE.
"""Read everything the checks need from one host in one call, changing nothing.

Run through a bastion, every Ansible task costs a round trip, so the role reads the agent's
health, the package, the service, the processes and the system here in one go, and judges the
results on the control node (filter_plugins/mde_linux_checks.py). Each section is read on its
own: one that fails reports an error and the rest still arrive.

It runs with the host's Python, so it keeps to what Python 3.6 has (RHEL 8's platform-python).
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: mde_linux_checks_probe
short_description: Read Defender for Endpoint's state on a Linux host, read-only
description:
  - Reads mdatp's health (and its detail sections), threat history and exclusions, the mdatp package, the
    service, the Defender processes' memory and CPU, and the system facts the checks need, in one call.
  - Changes nothing on the host.
options:
  since:
    description: Epoch seconds. Logs, SELinux denials and crash dumps are counted from then.
    type: float
    default: 0
  sample_seconds:
    description: How long to sample the Defender processes' CPU use. 0 skips the sample.
    type: float
    default: 0
  wait_for_engine:
    description:
      - Seconds to wait, before reading mdatp, for the antivirus engine to report it has loaded (a fresh start or a
        reboot takes a while). 0 does not wait.
    type: float
    default: 0
  sections:
    description: Which sections to read.
    type: list
    elements: str
    default: [mdatp, package, service, processes, system, logs, managed]
author:
  - Craig Thacker
"""

RETURN = r"""
probe:
  description: One key per section read, each a mapping, or a mapping with error when the section could not be read.
  returned: always
  type: dict
"""

import calendar
import json
import os
import re
import shutil
import time

from ansible.module_utils.basic import AnsibleModule

MDATP_PATHS = ("/usr/bin/mdatp", "/opt/microsoft/mdatp/sbin/wdavdaemonclient")
HEALTH_LINE = re.compile(r"^([a-z][a-z0-9_]*)\s+:\s?(.*)$")
DETAIL_SECTIONS = ("antivirus", "definitions", "edr", "engine", "features", "permissions")
SERVICE_PROPERTIES = (
    "ActiveState",
    "SubState",
    "UnitFileState",
    "NRestarts",
    "MainPID",
    "ExecMainStartTimestampMonotonic",
    "ExecMainStartTimestamp",
    "Result",
    "ExecMainStatus",
    "MemoryCurrent",
    "TasksCurrent",
)
DEFENDER_DIRS = ("/opt/microsoft/mdatp", "/var/opt/microsoft/mdatp", "/var/log/microsoft/mdatp")
FREE_SPACE_PATHS = ("/opt", "/var", "/var/log", "/tmp")
ERROR_LOG = "/var/log/microsoft/mdatp/microsoft_defender_core_err.log"
ERROR_LOG_LINE = re.compile(r"^\[\d+\]\[\d+\]\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)? UTC\]\[(\w+)\]")
AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_TIME = re.compile(r"msg=audit\((\d+(?:\.\d+)?):")
CRASH_DIR = "/var/opt/microsoft/mdatp/crash"
MANAGED_CONFIG = "/etc/opt/microsoft/mdatp/managed/mdatp_managed.json"
ONBOARDING_FILE = "/etc/opt/microsoft/mdatp/mdatp_onboard.json"
# Kept short: these go back to the control node through the bastion.
MAX_LINES = 20


def parse_health_value(raw):
    """One value from `mdatp health` text output, and whether it carries [managed].

    The text output, not --output json, is used: its field names are the documented ones
    (https://learn.microsoft.com/en-us/defender-endpoint/health-status), the JSON's are not.
    """
    raw = raw.strip()
    managed = False
    if raw.endswith("[managed]"):
        managed = True
        raw = raw[: -len("[managed]")].rstrip()
    if raw == "unavailable":
        return None, managed
    if raw in ("true", "false"):
        return raw == "true", managed
    if raw.startswith("[") and raw.endswith("]"):
        try:
            return json.loads(raw), managed
        except ValueError:
            return raw, managed
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1], managed
    if re.match(r"^-?\d+$", raw):
        return int(raw), managed
    return raw, managed


def parse_health(text):
    fields, managed = {}, []
    for line in text.splitlines():
        match = HEALTH_LINE.match(line.rstrip())
        if not match:
            continue  # the "ATTENTION: No license found" banner and blank lines
        value, is_managed = parse_health_value(match.group(2))
        fields[match.group(1)] = value
        if is_managed:
            managed.append(match.group(1))
    return fields, managed


class Probe(object):
    def __init__(self, module):
        self.module = module
        self.since = module.params["since"]
        self.env = {"LANG": "C", "LC_ALL": "C"}

    def run(self, args, check=False):
        rc, out, err = self.module.run_command(args, environ_update=self.env)
        if check and rc != 0:
            raise RuntimeError("%s exited %s: %s" % (" ".join(args), rc, (err or out).strip()[:500]))
        return rc, out, err

    def which(self, name):
        found = shutil.which(name)
        if found:
            return found
        for directory in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
            candidate = os.path.join(directory, name)
            if os.access(candidate, os.X_OK):
                return candidate
        return None

    # --- mdatp ------------------------------------------------------------------------------

    def mdatp(self):
        path = self.which("mdatp") or next((p for p in MDATP_PATHS if os.access(p, os.X_OK)), None)
        if not path:
            return {"present": False}
        result = {"present": True, "path": path}
        rc, out, err = self.run([path, "version"])
        result["version_rc"] = rc
        match = re.search(r"Product version:\s*(\S+)", out)
        result["version"] = match.group(1) if match else None
        result["license_banner"] = "No license found" in out + err

        wait = self.module.params["wait_for_engine"]
        if wait > 0:
            started = time.time()
            status = None
            while True:
                rc, out, _ = self.run([path, "health", "--field", "engine_load_status"])
                status, _ = parse_health_value(out.strip().splitlines()[-1] if out.strip() else "")
                if status == "Engine load succeeded" or time.time() - started >= wait:
                    break
                time.sleep(3)
            result["engine_wait"] = {
                "seconds": round(time.time() - started, 1),
                "status": status,
                "loaded": status == "Engine load succeeded",
                "timeout": wait,
            }

        started = time.time()
        rc, out, err = self.run([path, "health"])
        result["health_seconds"] = round(time.time() - started, 3)
        result["health_rc"] = rc
        result["health_text"] = out
        result["health"], result["managed_fields"] = parse_health(out)
        if rc != 0 or not result["health"]:
            result["health_error"] = (err or out).strip()[:1000]

        details = {}
        for section in DETAIL_SECTIONS:
            rc, out, err = self.run([path, "health", "--details", section])
            fields, managed = parse_health(out)
            details[section] = {"rc": rc, "fields": fields, "managed_fields": managed}
        result["details"] = details

        rc, out, err = self.run([path, "health", "--output", "json"])
        result["health_json"] = self.json_or_none(out)

        rc, out, err = self.run([path, "threat", "list", "--output", "json"])
        result["threats"] = self.json_or_none(out)
        rc, out, err = self.run([path, "exclusion", "list", "--output", "json"])
        result["exclusions"] = self.json_or_none(out)
        return result

    @staticmethod
    def json_or_none(text):
        start = text.find("{")
        if start < 0:
            return None
        try:
            return json.loads(text[start:])
        except ValueError:
            return None

    # --- The package --------------------------------------------------------------------------

    def package(self):
        rpm, dpkg = self.which("rpm"), self.which("dpkg-query")
        if rpm and self.run([rpm, "-q", "--quiet", "rpm"])[0] == 0:
            return self.rpm_package(rpm)
        if dpkg:
            return self.deb_package(dpkg)
        return {"manager": None}

    def rpm_package(self, rpm):
        result = {"manager": "rpm"}
        query = "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{SIGPGP:pgpsig}\t%{RSAHEADER:pgpsig}\n"
        rc, out, _ = self.run([rpm, "-q", "mdatp", "--qf", query])
        installed = []
        if rc == 0:
            for line in out.splitlines():
                parts = line.split("\t")
                if len(parts) < 7:
                    continue
                signature = parts[5] if parts[5] != "(none)" else parts[6]
                key = re.search(r"Key ID ([0-9a-fA-F]+)", signature)
                installed.append(
                    {
                        "name": parts[0],
                        "version": parts[1],
                        "release": parts[2],
                        "arch": parts[3],
                        "installed_at": int(parts[4]) if parts[4].isdigit() else None,
                        "signature": signature if signature != "(none)" else None,
                        "key_id": key.group(1).lower()[-8:] if key else None,
                    }
                )
        result["installed"] = installed
        if installed:
            rc, out, err = self.run([rpm, "-V", "--nofiles", "mdatp"])
            result["dependencies_rc"], result["dependencies_output"] = rc, (out + err).strip()[:2000]
            rc, out, err = self.run([rpm, "-V", "mdatp"])
            result["verify_rc"] = rc
            result["verify_lines"] = [line for line in (out + err).splitlines() if line.strip()][:200]
            rc, out, _ = self.run([rpm, "-qR", "mdatp"])
            result["requires"] = sorted(set(line.strip() for line in out.splitlines() if line.strip()))
        rc, out, _ = self.run([rpm, "-q", "gpg-pubkey", "--qf", "%{VERSION}\t%{SUMMARY}\n"])
        result["keys"] = [line.split("\t")[0].lower() for line in out.splitlines() if rc == 0 and line.strip()]
        return result

    def deb_package(self, dpkg):
        result = {"manager": "dpkg"}
        rc, out, _ = self.run([dpkg, "-W", "-f", "${Package}\t${Version}\t${Architecture}\t${Status}\t${Depends}\n", "mdatp"])
        installed = []
        if rc == 0:
            for line in out.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4 and parts[3].endswith(" installed"):
                    version, _, release = parts[1].rpartition("-")
                    installed.append(
                        {
                            "name": parts[0],
                            "version": version or parts[1],
                            "release": release if version else "",
                            "arch": parts[2],
                            "installed_at": None,
                            "signature": None,
                            "key_id": None,
                        }
                    )
                    result["requires"] = sorted(d.strip() for d in (parts[4] if len(parts) > 4 else "").split(",") if d.strip())
        result["installed"] = installed
        if installed:
            rc, out, err = self.run(["dpkg", "--verify", "mdatp"])
            result["verify_rc"] = rc
            result["verify_lines"] = [line for line in (out + err).splitlines() if line.strip()][:200]
            rc, out, err = self.run(["dpkg", "--audit", "mdatp"])
            result["dependencies_rc"], result["dependencies_output"] = rc, (out + err).strip()[:2000]
        result["keys"] = []
        return result

    # --- The service and its processes -----------------------------------------------------

    def service(self):
        systemctl = self.which("systemctl")
        if not systemctl:
            return {"systemd": False}
        rc, out, err = self.run([systemctl, "show", "mdatp", "-p", ",".join(SERVICE_PROPERTIES)])
        properties = {}
        for line in out.splitlines():
            key, _, value = line.partition("=")
            properties[key] = value
        for key in ("NRestarts", "MainPID", "ExecMainStatus", "ExecMainStartTimestampMonotonic"):
            if properties.get(key, "").isdigit():
                properties[key] = int(properties[key])
        properties["systemd"] = True
        rc, out, _ = self.run([systemctl, "is-active", "fapolicyd"])
        properties["fapolicyd_active"] = out.strip() == "active"
        return properties

    @staticmethod
    def defender_pids():
        pids = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open("/proc/%s/cmdline" % entry, "rb") as handle:
                    argv = handle.read().split(b"\0")
                with open("/proc/%s/comm" % entry) as handle:
                    comm = handle.read().strip()
            except (IOError, OSError):
                continue
            exe = argv[0].decode("utf-8", "replace") if argv and argv[0] else ""
            if exe.startswith("/opt/microsoft/mdatp/") or comm.startswith("wdavdaemon") or comm == "telemetryd_v2":
                role = argv[1].decode("utf-8", "replace") if len(argv) > 1 and argv[1] and not argv[1].startswith(b"-") else "main"
                pids.append({"pid": int(entry), "comm": comm, "role": role, "exe": exe})
        return pids

    @staticmethod
    def cpu_ticks(pid):
        try:
            with open("/proc/%d/stat" % pid) as handle:
                fields = handle.read().rsplit(")", 1)[1].split()
            return int(fields[11]) + int(fields[12])  # utime + stime
        except (IOError, OSError, IndexError, ValueError):
            return None

    @staticmethod
    def rss_kib(pid):
        try:
            with open("/proc/%d/status" % pid) as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        except (IOError, OSError, ValueError):
            pass
        return None

    def processes(self):
        pids = self.defender_pids()
        seconds = self.module.params["sample_seconds"]
        result = {"processes": pids, "sample_seconds": seconds}
        if seconds > 0 and pids:
            before = dict((p["pid"], self.cpu_ticks(p["pid"])) for p in pids)
            started = time.time()
            time.sleep(seconds)
            elapsed = time.time() - started
            ticks = os.sysconf("SC_CLK_TCK")
            total = 0
            for process in pids:
                after = self.cpu_ticks(process["pid"])
                if after is not None and before.get(process["pid"]) is not None:
                    process["cpu_percent"] = round((after - before[process["pid"]]) / ticks / elapsed * 100, 2)
                    total += process["cpu_percent"]
            result["cpu_percent"] = round(total, 2)
        for process in pids:
            process["rss_kib"] = self.rss_kib(process["pid"])
        result["memory_mib"] = round(sum(p["rss_kib"] or 0 for p in pids) / 1024.0, 1)
        return result

    # --- The system -----------------------------------------------------------------------------

    def system(self):
        result = {}
        result["boot_id"] = self.read("/proc/sys/kernel/random/boot_id")
        result["kernel"] = os.uname()[2]
        uptime = self.read("/proc/uptime")
        result["uptime_seconds"] = float(uptime.split()[0]) if uptime else None
        result["fips_enabled"] = self.read("/proc/sys/crypto/fips_enabled") == "1"
        result["btf"] = os.path.exists("/sys/kernel/btf/vmlinux")
        result["cpus"] = os.cpu_count()
        meminfo = {}
        for line in (self.read("/proc/meminfo") or "").splitlines():
            key, _, value = line.partition(":")
            if value.strip().endswith("kB"):
                meminfo[key] = int(value.split()[0])
        result["memory_total_mib"] = round(meminfo.get("MemTotal", 0) / 1024.0, 1)
        result["memory_available_mib"] = round(meminfo.get("MemAvailable", 0) / 1024.0, 1)

        free = {}
        for path in FREE_SPACE_PATHS:
            try:
                stat = os.statvfs(path)
                free[path] = round(stat.f_bavail * stat.f_frsize / 1048576.0, 1)
            except OSError:
                free[path] = None
        result["free_mib"] = free
        result["filesystems"] = self.filesystems()
        result["defender_disk_mib"] = dict((d, self.disk_usage_mib(d)) for d in DEFENDER_DIRS)

        selinux = {"present": os.path.isdir("/sys/fs/selinux") and os.path.exists("/sys/fs/selinux/enforce")}
        if selinux["present"]:
            selinux["mode"] = "enforcing" if self.read("/sys/fs/selinux/enforce") == "1" else "permissive"
            semodule = self.which("semodule")
            if semodule:
                rc, out, _ = self.run([semodule, "-l"])
                selinux["modules"] = sorted(m.split()[0] for m in out.splitlines() if re.search(r"mdatp|wdav", m)) if rc == 0 else None
        else:
            selinux["mode"] = "disabled"
        result["selinux"] = selinux

        timedatectl = self.which("timedatectl")
        if timedatectl:
            rc, out, _ = self.run([timedatectl, "show", "-p", "NTPSynchronized", "--value"])
            result["time_synchronised"] = out.strip() == "yes" if rc == 0 else None
        else:
            result["time_synchronised"] = None
        return result

    @staticmethod
    def read(path):
        try:
            with open(path) as handle:
                return handle.read().strip()
        except (IOError, OSError):
            return None

    def filesystems(self):
        mounts = []
        for line in (self.read("/proc/mounts") or "").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                mounts.append((parts[1].replace("\\040", " "), parts[2]))
        result = {}
        for path in ("/", "/opt", "/var", "/tmp", "/home"):
            best = max(
                (m for m in mounts if path == m[0] or path.startswith(m[0].rstrip("/") + "/")), key=lambda m: len(m[0]), default=None
            )
            result[path] = best[1] if best else None
        return result

    @staticmethod
    def disk_usage_mib(directory):
        total = 0
        if not os.path.isdir(directory):
            return None
        for root, _, files in os.walk(directory):
            for name in files:
                try:
                    total += os.lstat(os.path.join(root, name)).st_blocks * 512
                except OSError:
                    continue
        return round(total / 1048576.0, 1)

    # --- What happened since the run started -----------------------------------------------

    def logs(self):
        since = self.since
        result = {"since": since}
        result["error_log"] = self.error_log(since)
        result["avc_denials"] = self.avc_denials(since)
        result["journal_errors"] = self.journal_errors(since)
        result["core_dumps"] = self.core_dumps(since)
        crash = []
        if os.path.isdir(CRASH_DIR):
            for name in sorted(os.listdir(CRASH_DIR)):
                path = os.path.join(CRASH_DIR, name)
                try:
                    if name != "crash.lock" and os.path.getmtime(path) >= since:
                        crash.append(name)
                except OSError:
                    continue
        result["crash_files"] = crash
        return result

    @staticmethod
    def tail(lines):
        return lines[-MAX_LINES:]

    def error_log(self, since):
        counts, sample = {}, []
        try:
            with open(ERROR_LOG, errors="replace") as handle:
                for line in handle:
                    match = ERROR_LOG_LINE.match(line)
                    if not match:
                        continue
                    stamp = calendar.timegm(time.strptime(match.group(1), "%Y-%m-%d %H:%M:%S"))
                    if stamp < since:
                        continue
                    level = match.group(2)
                    counts[level] = counts.get(level, 0) + 1
                    if level in ("error", "fatal", "critical"):
                        sample.append(line.rstrip()[:400])
        except (IOError, OSError) as exc:
            return {"error": str(exc)}
        return {"counts": counts, "lines": self.tail(sample)}

    def avc_denials(self, since):
        if not os.path.exists(AUDIT_LOG):
            return {"available": False, "count": 0, "lines": []}
        found = []
        try:
            with open(AUDIT_LOG, errors="replace") as handle:
                for line in handle:
                    if "avc:  denied" not in line:
                        continue
                    match = AUDIT_TIME.search(line)
                    if match and float(match.group(1)) < since:
                        continue
                    if re.search(r'comm="(wdavdaemon|mdatp|telemetryd_v2)"|mdatp_|wdav', line):
                        found.append(line.rstrip()[:600])
        except (IOError, OSError) as exc:
            return {"available": False, "error": str(exc), "count": 0, "lines": []}
        return {"available": True, "count": len(found), "lines": self.tail(found)}

    def journal_errors(self, since):
        journalctl = self.which("journalctl")
        if not journalctl:
            return {"available": False, "count": 0, "lines": []}
        rc, out, _ = self.run(
            [journalctl, "-u", "mdatp", "--since", "@%d" % int(since), "-p", "err", "--no-pager", "-q", "-o", "short-iso"]
        )
        lines = [line for line in out.splitlines() if line.strip()] if rc == 0 else []
        return {"available": rc == 0, "count": len(lines), "lines": self.tail(lines)}

    def core_dumps(self, since):
        found = []
        coredumpctl = self.which("coredumpctl")
        if coredumpctl:
            rc, out, _ = self.run([coredumpctl, "list", "--since", "@%d" % int(since), "--no-pager", "--no-legend", "-q"])
            if rc == 0:
                found.extend(line.strip() for line in out.splitlines() if re.search(r"wdav|mdatp|telemetryd", line))
        directory = "/var/lib/systemd/coredump"
        if os.path.isdir(directory):
            for name in os.listdir(directory):
                path = os.path.join(directory, name)
                try:
                    if re.search(r"wdav|mdatp", name) and os.path.getmtime(path) >= since and name not in " ".join(found):
                        found.append(name)
                except OSError:
                    continue
        return {"count": len(found), "lines": self.tail(found)}

    # --- Configuration --------------------------------------------------------------------------

    def managed(self):
        result = {
            "path": MANAGED_CONFIG,
            "present": os.path.exists(MANAGED_CONFIG),
            "onboarding_file_present": os.path.exists(ONBOARDING_FILE),
        }
        if result["present"]:
            try:
                with open(MANAGED_CONFIG) as handle:
                    result["content"] = json.load(handle)
                result["valid"] = True
            except ValueError as exc:
                result["valid"], result["error"] = False, str(exc)
            except (IOError, OSError) as exc:
                result["valid"], result["error"] = None, str(exc)
        return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            since=dict(type="float", default=0),
            sample_seconds=dict(type="float", default=0),
            wait_for_engine=dict(type="float", default=0),
            sections=dict(type="list", elements="str", default=["mdatp", "package", "service", "processes", "system", "logs", "managed"]),
        ),
        supports_check_mode=True,
    )
    probe = Probe(module)
    result = {"taken_at": time.time()}
    for section in module.params["sections"]:
        reader = getattr(probe, section, None)
        if reader is None or section.startswith("_") or section in ("run", "which", "read", "tail"):
            module.fail_json(msg="unknown section %s" % section)
        try:
            result[section] = reader()
        except Exception as exc:  # each section on its own: one failure must not hide the rest
            result[section] = {"error": "%s: %s" % (type(exc).__name__, exc)}
    result["finished_at"] = time.time()
    module.exit_json(changed=False, probe=result)


if __name__ == "__main__":
    main()
