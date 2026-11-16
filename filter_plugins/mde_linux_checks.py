# -*- coding: utf-8 -*-
# Copyright (c) 2026 Craig Thacker (Libre DevOps). MIT licence: see LICENSE.
"""Judge what the probes read on a host, on the control node, as test results.

The role's tasks only gather: the probe module reads the host (before the checks, after them,
and after a reboot), and a few tasks act (the EICAR test, a scan, an update). This filter turns
all of that into the suite of results libre_devops.test_results_report reads
(libre_devops.test_results/v1), one check per thing that can go wrong, each with an id that
never changes meaning.

Every check is written against what mdatp documents (the health fields at
https://learn.microsoft.com/en-us/defender-endpoint/health-status) and what was seen on real
hosts, and copes with fields a version does not have: a field added in a later release makes
its check skip on an older one, never fail.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import datetime
import re

UTC = datetime.timezone.utc
SUITE_SCHEMA = "libre_devops.test_results/v1"
BASELINE_SCHEMA = "libre_devops.mde_linux_checks_baseline/v1"

DOCS = {
    "health": "https://learn.microsoft.com/en-us/defender-endpoint/health-status",
    "resources": "https://learn.microsoft.com/en-us/defender-endpoint/linux-resources",
    "preferences": "https://learn.microsoft.com/en-us/defender-endpoint/linux-preferences",
    "prerequisites": "https://learn.microsoft.com/en-us/defender-endpoint/mde-linux-prerequisites",
    "connectivity": "https://learn.microsoft.com/en-us/defender-endpoint/linux-support-connectivity",
    "ebpf": "https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf",
    "releases": "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-releases",
    "performance": "https://learn.microsoft.com/en-us/defender-endpoint/linux-support-perf",
    "offline_updates": "https://learn.microsoft.com/en-us/defender-endpoint/linux-support-offline-security-intelligence-update",
    "exclusions": "https://learn.microsoft.com/en-us/defender-endpoint/linux-exclusions",
}

# Microsoft's package signing keys: the short ids rpm shows (rpm -q gpg-pubkey).
MICROSOFT_KEYS = {"be1229cf": "Microsoft (Release signing)", "f748182b": "Microsoft Corporation - General GPG Signer"}

# File systems real-time protection and quick and full scans support (the prerequisites page).
RTP_FILESYSTEMS = {
    "btrfs",
    "ecryptfs",
    "ext2",
    "ext3",
    "ext4",
    "fuseblk",
    "jfs",
    "overlay",
    "ramfs",
    "reiserfs",
    "tmpfs",
    "udf",
    "vfat",
    "xfs",
}

ENGINE_LOADED = "Engine load succeeded"
NOT_ONBOARDED_ISSUES = {"missing license"}

# Settings in mdatp_managed.json, and the health fields Microsoft documents as showing [managed]
# once the agent has taken them up (linux-preferences, "Verifying that the mdatp_managed.json file
# is working as expected").
MANAGED_FIELDS = (
    (("antivirusEngine", "enforcementLevel"), ("real_time_protection_enabled", "passive_mode_enabled")),
    (("antivirusEngine", "passiveMode"), ("passive_mode_enabled",)),
    (("cloudService", "enabled"), ("cloud_enabled",)),
    (("cloudService", "automaticSampleSubmissionConsent"), ("cloud_automatic_sample_submission_consent",)),
    (("cloudService", "automaticDefinitionUpdateEnabled"), ("automatic_definition_update_enabled",)),
)

# Health fields that must not change when the agent is upgraded on the same host.
IDENTITY_FIELDS = ("machine_guid", "edr_machine_id", "org_id")


# --- Small helpers ---------------------------------------------------------------------------


def version_tuple(value):
    return tuple(int(part) for part in re.findall(r"\d+", str(value or ""))) or (0,)


def get(mapping, *path):
    for key in path:
        if not isinstance(mapping, dict):
            return None
        mapping = mapping.get(key)
    return mapping


def nested(mapping, path):
    return get(mapping, *path)


def plural(count, word, words=None):
    return "%d %s" % (count, word if count == 1 else (words or word + "s"))


BANNER = re.compile(r"^ATTENTION: No license found\..*$", re.M)


def action_output(action):
    """A command's output for people: stdout, stderr and Ansible's message, without mdatp's banner."""
    parts = [action.get(k) for k in ("output", "stdout", "stderr")]
    msg = action.get("msg") or ""
    if msg and msg != "The command exited with a non-zero return code.":
        parts.append(msg)
    text = "\n".join(p for p in parts if p)
    return BANNER.sub("", text).strip()


def shown(value):
    """A health value as mdatp prints it: true, false, a string, a list."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "unavailable"
    return str(value)


def listing(items, limit=8):
    items = [str(i) for i in items]
    shown = ", ".join(items[:limit])
    return shown + (" and %d more" % (len(items) - limit) if len(items) > limit else "")


def parse_mdatp_date(value):
    """mdatp's dates: "Nov 15, 2026 at 09:08:22 PM UTC", ISO 8601, or epoch milliseconds."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.isdigit():
        number = int(text)
        return datetime.datetime.fromtimestamp(number / 1000.0 if number > 10**11 else number, UTC).replace(tzinfo=None)
    text = re.sub(r"\s+(UTC|GMT)$", "", text)
    for pattern in ("%b %d, %Y at %I:%M:%S %p", "%b %d, %Y at %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(text.replace("Z", ""), pattern)
        except ValueError:
            continue
    return None


class Suite(object):
    """Collects checks in order, skipping the ones mde_linux_checks_skip names."""

    def __init__(self, settings):
        self.checks = []
        self.skip = set(settings.get("skip") or [])

    def add(self, check_id, name, status, severity, category, detail, **extra):
        if check_id in self.skip and status != "skipped":
            status, detail = "skipped", "Skipped by mde_linux_checks_skip."
            extra = dict((k, v) for k, v in extra.items() if k == "docs")
        check = {"id": check_id, "name": name, "status": status, "severity": severity, "category": category, "detail": detail}
        # A metric is a number or absent: the report's format has no room for a null one.
        if extra.get("metrics"):
            extra["metrics"] = dict((k, v) for k, v in extra["metrics"].items() if isinstance(v, (int, float)) and not isinstance(v, bool))
        for key, value in extra.items():
            if value not in (None, "", {}, []):
                check[key] = value
        self.checks.append(check)
        return check


# --- The checks ------------------------------------------------------------------------------


class Evaluation(object):
    def __init__(self, data):
        self.data = data
        self.settings = data.get("settings") or {}
        probes = data.get("probes") or {}
        self.before = probes.get("before") or {}
        self.after = probes.get("after") or {}
        self.rebooted = probes.get("rebooted")
        self.actions = data.get("actions") or {}
        self.baseline = data.get("baseline")
        self.suite = Suite(self.settings)
        self.health = get(self.after, "mdatp", "health") or {}
        self.managed_fields = set(get(self.after, "mdatp", "managed_fields") or [])
        self.details = get(self.after, "mdatp", "details") or {}
        self.licensed = self.health.get("licensed") is True
        self.online = bool(self.settings.get("online", True))
        # The log-based checks look back this far, so a health check of a host in use sees what
        # happened before the run, not only during it.
        hours = float(self.settings.get("history_hours", 24))
        self.window = "in the last %g h" % hours if hours > 0 else "since the checks started"
        self.installed = bool(get(self.after, "package", "installed")) and bool(get(self.after, "mdatp", "present"))

    def detail_field(self, section, field):
        return get(self.details, section, "fields", field)

    # The level the antivirus really runs at. antivirus_enforcement_level arrived in
    # 101.26052.0012; before it, the level follows from passive mode and real-time protection.
    def enforcement_level(self):
        level = self.health.get("antivirus_enforcement_level") or self.detail_field("antivirus", "enforcement_level")
        if level:
            return level, "antivirus_enforcement_level"
        if self.health.get("passive_mode_enabled") is True:
            return "passive", "passive_mode_enabled"
        if self.health.get("real_time_protection_enabled") is True:
            return "real_time", "real_time_protection_enabled"
        if self.health.get("real_time_protection_enabled") is False:
            return "on_demand", "real_time_protection_enabled"
        return None, None

    def expect_onboarded(self):
        wanted = str(self.settings.get("onboarded", "auto")).lower()
        if wanted in ("true", "yes"):
            return True
        if wanted in ("false", "no"):
            return False
        return bool(get(self.after, "managed", "onboarding_file_present")) or self.licensed

    # Without the agent these still mean something: whether the host is ready for it.
    WITHOUT_AGENT = {
        "agent_installed",
        "system_requirements",
        "disk_space_for_updates",
        "filesystems_supported",
        "time_synchronised",
        "selinux_mode_unchanged",
        "upgrade_compared",
    }

    def run(self):
        self.installation()
        self.stability()
        self.protection()
        self.configuration()
        self.onboarding()
        self.system()
        self.resources()
        self.reboot()
        self.upgrade()
        if not self.installed:
            # One root cause, not a cascade: every check that needs the agent says it was not
            # checked, and agent_installed carries the failure.
            for check in self.suite.checks:
                if check["id"] in self.WITHOUT_AGENT or check["status"] == "skipped":
                    continue
                for key in ("metrics", "output", "remediation", "expected", "actual", "docs"):
                    check.pop(key, None)
                check["status"] = "skipped"
                check["detail"] = "Not checked: mdatp is not installed."
        return self.suite.checks

    # --- Installation ------------------------------------------------------------------------

    def installation(self):
        add = self.suite.add
        package = self.after.get("package") or {}
        installed = package.get("installed") or []
        mdatp = self.after.get("mdatp") or {}
        version = mdatp.get("version") or (installed[0]["version"] if installed else None)
        if "error" in package and not installed:
            add(
                "agent_installed",
                "The mdatp package is installed",
                "error",
                "critical",
                "installation",
                "Could not read the package database: %s" % package["error"],
            )
        elif not installed:
            add(
                "agent_installed",
                "The mdatp package is installed",
                "failed",
                "critical",
                "installation",
                "mdatp is not installed.",
                remediation="Install it (libre_devops.mde_linux) before running the checks.",
            )
        elif len(installed) > 1:
            add(
                "agent_installed",
                "The mdatp package is installed",
                "failed",
                "critical",
                "installation",
                "%s of mdatp are installed: %s." % (len(installed), listing(p["version"] + "-" + p["release"] for p in installed)),
                remediation="Remove the extra versions: an interrupted upgrade can leave two.",
            )
        elif not mdatp.get("present"):
            add(
                "agent_installed",
                "The mdatp package is installed",
                "failed",
                "critical",
                "installation",
                "The package is installed but the mdatp command is missing.",
            )
        else:
            p = installed[0]
            add(
                "agent_installed",
                "The mdatp package is installed",
                "passed",
                "critical",
                "installation",
                "mdatp %s-%s (%s)." % (p["version"], p["release"], p["arch"]),
            )

        expected = str(self.settings.get("expected_version") or "")
        if not expected:
            add(
                "agent_version",
                "The expected version of mdatp is installed",
                "skipped",
                "critical",
                "installation",
                "No expected version given (mde_linux_checks_expected_version).",
            )
        elif not version:
            add(
                "agent_version",
                "The expected version of mdatp is installed",
                "error",
                "critical",
                "installation",
                "Could not read the installed version.",
            )
        else:
            add(
                "agent_version",
                "The expected version of mdatp is installed",
                "passed" if version == expected else "failed",
                "critical",
                "installation",
                "Installed %s, expected %s." % (version, expected),
                expected=expected,
                actual=version,
            )

        if package.get("manager") == "rpm" and installed:
            key = installed[0].get("key_id")
            if key in MICROSOFT_KEYS:
                add(
                    "package_signature",
                    "The package is signed with a Microsoft key",
                    "passed",
                    "high",
                    "installation",
                    "Signed with key %s (%s)." % (key, MICROSOFT_KEYS[key]),
                )
            else:
                add(
                    "package_signature",
                    "The package is signed with a Microsoft key",
                    "failed",
                    "high",
                    "installation",
                    "Signed with key %s, not a Microsoft key." % key if key else "The installed package carries no signature.",
                    expected="one of %s" % ", ".join(sorted(MICROSOFT_KEYS)),
                    actual=key or "unsigned",
                    remediation="Install mdatp only from packages.microsoft.com or a mirror of it.",
                )
        elif installed:
            add(
                "package_signature",
                "The package is signed with a Microsoft key",
                "skipped",
                "high",
                "installation",
                "Debian packages keep no signature once installed: check the file's checksum before installing it.",
            )

        if installed:
            deps_ok = package.get("dependencies_rc") == 0
            add(
                "package_dependencies",
                "The package's dependencies are installed",
                "passed" if deps_ok else "failed",
                "high",
                "installation",
                "Every dependency is installed." if deps_ok else "Missing dependencies.",
                output=None if deps_ok else package.get("dependencies_output"),
            )
            changed = [line for line in package.get("verify_lines") or [] if not re.match(r"^\S+\s+c\s", line)]
            add(
                "package_files_intact",
                "The package's files are as installed",
                "passed" if not changed else "failed",
                "medium",
                "installation",
                "No file differs from the package." if not changed else "%s differ from the package." % plural(len(changed), "file"),
                output="\n".join(changed) if changed else None,
                remediation="Reinstall mdatp, and find what changed the files." if changed else None,
            )

        if not mdatp.get("present"):
            return
        fields = len(self.health)
        if fields and mdatp.get("health_rc") == 0:
            add(
                "health_readable",
                "mdatp health answers",
                "passed",
                "critical",
                "installation",
                "%s fields in %.0f ms." % (fields, (mdatp.get("health_seconds") or 0) * 1000),
                metrics={"health_seconds": mdatp.get("health_seconds") or 0, "health_fields": fields},
            )
        else:
            add(
                "health_readable",
                "mdatp health answers",
                "error",
                "critical",
                "installation",
                "mdatp health gave no fields: %s" % (mdatp.get("health_error") or "exit %s" % mdatp.get("health_rc")),
                remediation="Check the service is running: systemctl status mdatp.",
                docs=DOCS["resources"],
            )

    # --- Stability -----------------------------------------------------------------------------

    def stability(self):
        add = self.suite.add
        service = self.after.get("service") or {}
        before_service = self.before.get("service") or {}
        if not service.get("systemd"):
            add(
                "service_running",
                "The mdatp service is running",
                "error",
                "critical",
                "stability",
                "Could not read the service: %s" % service.get("error", "systemd not found"),
            )
        else:
            running = service.get("ActiveState") == "active" and service.get("SubState") == "running"
            add(
                "service_running",
                "The mdatp service is running",
                "passed" if running else "failed",
                "critical",
                "stability",
                "mdatp is %s (%s)." % (service.get("ActiveState"), service.get("SubState")),
                remediation=None if running else "journalctl -u mdatp shows why it stopped.",
            )
            enabled = service.get("UnitFileState") == "enabled"
            add(
                "service_enabled",
                "The mdatp service starts at boot",
                "passed" if enabled else "failed",
                "critical",
                "stability",
                "The unit is %s." % service.get("UnitFileState"),
                remediation=None
                if enabled
                else "systemctl enable mdatp. Versions 101.26042.0000 to 0009 could leave it disabled after an upgrade.",
                docs=None if enabled else DOCS["releases"],
            )

            # systemd counts its automatic restarts (Restart=) since the unit was last started by hand:
            # a crash that systemd recovered from shows here even if it happened before the run.
            restarts = service["NRestarts"] if isinstance(service.get("NRestarts"), int) else 0
            if self.rebooted and isinstance(get(self.rebooted, "service", "NRestarts"), int):
                restarts += self.rebooted["service"]["NRestarts"]
            notes = []
            if restarts:
                notes.append("restarted by systemd %s since it was last started" % plural(restarts, "time"))
            if before_service.get("MainPID") and service.get("MainPID") and before_service["MainPID"] != service["MainPID"]:
                notes.append("its main process changed from %s to %s during the checks" % (before_service["MainPID"], service["MainPID"]))
            add(
                "no_service_restarts",
                "The service has not been restarting",
                "passed" if not notes else "failed",
                "high",
                "stability",
                "No automatic restarts since it was last started, and the same main process throughout."
                if not notes
                else "; ".join(notes)[:1].upper() + "; ".join(notes)[1:] + ".",
                metrics={"restarts": restarts},
                remediation=None if not notes else "journalctl -u mdatp shows why it exited.",
            )

        crashes = []
        for probe in (self.after, self.rebooted or {}):
            logs = probe.get("logs") or {}
            crashes += get(logs, "core_dumps", "lines") or []
            crashes += ["crash file " + name for name in logs.get("crash_files") or []]
        add(
            "no_crashes",
            "No Defender process has crashed recently",
            "passed" if not crashes else "failed",
            "high",
            "stability",
            "No core dumps or crash files %s." % self.window
            if not crashes
            else "%s %s." % (plural(len(crashes), "crash", "crashes"), self.window),
            output="\n".join(crashes) if crashes else None,
            metrics={"crashes": len(crashes)},
            remediation=None if not crashes else "Collect mdatp diagnostic create and raise it with Microsoft.",
        )

        before_boot, after_boot = get(self.before, "system", "boot_id"), get(self.after, "system", "boot_id")
        if before_boot and after_boot:
            same = before_boot == after_boot
            add(
                "no_unexpected_reboot",
                "The host did not reboot on its own during the checks",
                "passed" if same else "failed",
                "critical",
                "stability",
                "Same boot throughout." if same else "The host rebooted during the checks (boot id changed).",
                remediation=None
                if same
                else "Look for a kernel panic or watchdog reset: 101.25102.0005 fixed real-time scanning of /dev/watchdog rebooting hosts.",
                docs=None if same else DOCS["releases"],
            )

        settle = self.actions.get("settle") or {}
        status = self.health.get("engine_load_status") or self.detail_field("engine", "engine_load_status")
        loaded = status == ENGINE_LOADED
        waited = settle.get("seconds")
        when = ""
        if loaded and waited is not None:
            when = " (already loaded when the checks started)" if waited < 3 else ", %.0f s after the checks started" % waited
        elif not loaded and waited is not None:
            when = " after waiting %.0f s" % waited
        add(
            "engine_loaded",
            "The antivirus engine is loaded",
            "passed" if loaded else "failed",
            "critical",
            "protection",
            "%s%s." % (status or "No engine status", when),
            metrics={"seconds_to_load": settle["seconds"]} if loaded and settle.get("seconds") is not None else None,
            remediation=None
            if loaded
            else "Look in /var/log/microsoft/mdatp/microsoft_defender_core_err.log. From 101.26062.0007 an engine "
            "that fails signature verification is not loaded.",
            docs=None if loaded else DOCS["releases"],
        )

        error_log = get(self.after, "logs", "error_log") or {}
        counts = error_log.get("counts") or {}
        serious = counts.get("fatal", 0) + counts.get("critical", 0)
        add(
            "error_log",
            "Defender has logged no fatal errors recently",
            "passed" if not serious else "failed",
            "info",
            "stability",
            "%s, %s, %s logged %s."
            % (
                plural(serious, "fatal or critical entry", "fatal or critical entries"),
                plural(counts.get("error", 0), "error"),
                plural(counts.get("warning", 0), "warning"),
                self.window,
            ),
            output="\n".join(error_log.get("lines") or []) or None,
            metrics={"errors": counts.get("error", 0), "warnings": counts.get("warning", 0), "fatal": serious},
        )

        journal = get(self.after, "logs", "journal_errors") or {}
        if journal.get("available"):
            count = journal.get("count", 0)
            add(
                "journal_errors",
                "The mdatp service has logged no errors to the journal recently",
                "passed" if not count else "failed",
                "low",
                "stability",
                "No error entries %s." % self.window
                if not count
                else "%s %s." % (plural(count, "error entry", "error entries"), self.window),
                output="\n".join(journal.get("lines") or []) or None,
                metrics={"entries": count},
            )

    # --- Protection ------------------------------------------------------------------------------

    def protection(self):
        add = self.suite.add
        health = self.health
        level, source = self.enforcement_level()
        managed = " [managed]" if source in self.managed_fields else ""
        expected = self.settings.get("expected_enforcement_level") or ""
        if not expected:
            add(
                "enforcement_level",
                "The antivirus runs at the expected enforcement level",
                "skipped",
                "high",
                "protection",
                "No expected level given (mde_linux_checks_expected_enforcement_level); it runs at %s." % (level or "an unknown level"),
            )
        elif level is None:
            add(
                "enforcement_level",
                "The antivirus runs at the expected enforcement level",
                "error",
                "high",
                "protection",
                "mdatp reports no enforcement level.",
            )
        else:
            add(
                "enforcement_level",
                "The antivirus runs at the expected enforcement level",
                "passed" if level == expected else "failed",
                "high",
                "protection",
                "%s%s." % (level, managed),
                expected=expected,
                actual=level,
                remediation=None if level == expected else "Set antivirusEngine.enforcementLevel in mdatp_managed.json.",
                docs=DOCS["preferences"],
            )

        if level in ("real_time", "audit"):
            enabled = health.get("real_time_protection_enabled") is True
            available = health.get("real_time_protection_available") is True
            ok = enabled and available
            add(
                "real_time_protection",
                "Real-time protection is enabled and working",
                "passed" if ok else "failed",
                "critical",
                "protection",
                "Enabled: %s, available: %s, subsystem: %s."
                % (
                    shown(health.get("real_time_protection_enabled")),
                    shown(health.get("real_time_protection_available")),
                    shown(health.get("real_time_protection_subsystem")),
                ),
                remediation=None
                if ok
                else "real_time_protection_available false means the subsystem (fanotify) failed: check "
                "conflicting_applications and the kernel.",
                docs=DOCS["health"],
            )
            subsystem = health.get("real_time_protection_subsystem")
            add(
                "real_time_subsystem",
                "Real-time protection has a working subsystem",
                "passed" if subsystem and subsystem != "unavailable" else "failed",
                "medium",
                "protection",
                "Served by %s." % subsystem if subsystem else "No subsystem: real-time protection is not operating.",
            )
        else:
            reason = (
                "Real-time protection is off by design at enforcement level %s." % level if level else "The enforcement level is unknown."
            )
            add("real_time_protection", "Real-time protection is enabled and working", "skipped", "critical", "protection", reason)
            add("real_time_subsystem", "Real-time protection has a working subsystem", "skipped", "medium", "protection", reason)

        events = health.get("supplementary_events_subsystem")
        btf = get(self.after, "system", "btf")
        if events == "ebpf":
            add("supplementary_events", "EDR events come from the eBPF provider", "passed", "high", "protection", "eBPF.")
        elif events == "netlink":
            add(
                "supplementary_events",
                "EDR events come from the eBPF provider",
                "failed",
                "medium",
                "protection",
                "The netlink fallback provider: EDR sees less. The kernel %s BTF (/sys/kernel/btf/vmlinux)." % ("has" if btf else "lacks"),
                remediation="Check the kernel's eBPF support.",
                docs=DOCS["ebpf"],
            )
        elif events == "auditd":
            add(
                "supplementary_events",
                "EDR events come from the eBPF provider",
                "failed",
                "high",
                "protection",
                "auditd, which Defender no longer supports from 101.24082.0004.",
                docs=DOCS["releases"],
            )
        else:
            add(
                "supplementary_events",
                "EDR events come from the eBPF provider",
                "failed" if events else "error",
                "high",
                "protection",
                "Supplementary events subsystem: %s." % (events or "not reported"),
                docs=DOCS["ebpf"],
            )

        conflicts = health.get("conflicting_applications")
        if isinstance(conflicts, list):
            add(
                "conflicting_applications",
                "No conflicting security software is running",
                "passed" if not conflicts else "failed",
                "high",
                "protection",
                "None." if not conflicts else "Conflicting: %s." % listing(conflicts),
                remediation=None
                if not conflicts
                else "Another fanotify-based product in blocking mode can hang the system: remove it, or run Defender passive.",
                docs=None if not conflicts else DOCS["prerequisites"],
            )
        else:
            add(
                "conflicting_applications",
                "No conflicting security software is running",
                "error",
                "high",
                "protection",
                "mdatp did not report conflicting_applications.",
            )

        # Found on a RHEL 9 VM with no route out: with cloud-delivered protection on, every detection
        # waited about 40 s for the cloud lookup to time out (EICAR in 40.5 s; 0.4 s with it off).
        cloud = health.get("cloud_enabled")
        eicar_seconds = (self.actions.get("eicar") or {}).get("seconds")
        if self.online:
            add(
                "offline_cloud_protection",
                "Cloud-delivered protection is off on a host that cannot reach the cloud",
                "skipped",
                "high",
                "protection",
                "The host is online (mde_linux_checks_online is true).",
            )
        elif cloud is None:
            add(
                "offline_cloud_protection",
                "Cloud-delivered protection is off on a host that cannot reach the cloud",
                "error",
                "high",
                "protection",
                "mdatp did not report cloud_enabled.",
            )
        else:
            measured = " (the EICAR test took %.1f s here)" % eicar_seconds if cloud and eicar_seconds else ""
            add(
                "offline_cloud_protection",
                "Cloud-delivered protection is off on a host that cannot reach the cloud",
                "passed" if cloud is False else "failed",
                "high",
                "protection",
                "cloud_enabled: false."
                if cloud is False
                else "cloud_enabled: true on a host that cannot reach the cloud: each lookup waits for the cloud to time out before "
                "the verdict%s." % measured,
                expected="false",
                actual=shown(cloud),
                remediation=None
                if cloud is False
                else "Set cloudService.enabled to false in mdatp_managed.json for hosts "
                "with no route to Microsoft: on a RHEL 9 test VM detections took 40 s with it on and 0.4 s with it off.",
                docs=None if cloud is False else DOCS["preferences"],
            )

        verification = self.detail_field("features", "engine_signature_verification")
        if verification is None:
            add(
                "engine_signature_verification",
                "The engine's signature is verified before it loads",
                "skipped",
                "medium",
                "protection",
                "This version does not report engine_signature_verification (it arrived with 101.26062.0007).",
            )
        else:
            add(
                "engine_signature_verification",
                "The engine's signature is verified before it loads",
                "passed" if verification == "enabled" else "failed",
                "medium",
                "protection",
                "engine_signature_verification: %s." % verification,
                docs=DOCS["releases"],
            )

        permissions = get(self.details, "permissions", "fields") or {}
        if not permissions:
            add(
                "folder_permissions",
                "Defender's folders have the permissions it needs",
                "skipped",
                "high",
                "protection",
                "This version does not report folder permissions (mdatp health --details permissions).",
            )
        else:
            bad = ["%s: %s" % (k, v) for k, v in sorted(permissions.items()) if v != "No permission issues"]
            add(
                "folder_permissions",
                "Defender's folders have the permissions it needs",
                "passed" if not bad else "failed",
                "high",
                "protection",
                "No permission issues in %s." % listing(sorted(permissions)) if not bad else "; ".join(bad) + ".",
                remediation=None if not bad else "Hardening that tightens /var/opt/microsoft or /var/log/microsoft breaks Defender.",
            )

        self.eicar(level)
        self.quick_scan()
        self.definitions()

        expiry_raw = health.get("product_expiration")
        expires = parse_mdatp_date(expiry_raw)
        minimum = int(self.settings.get("min_days_to_expiry", 30))
        if expiry_raw is None:
            add(
                "product_expiry",
                "This version is supported for long enough",
                "skipped" if not self.licensed else "error",
                "high",
                "protection",
                "mdatp reports product_expiration only once the device is onboarded."
                if not self.licensed
                else "mdatp reported no product_expiration.",
                docs=DOCS["releases"],
            )
        elif expires is None:
            add(
                "product_expiry",
                "This version is supported for long enough",
                "error",
                "high",
                "protection",
                "Could not read product_expiration %r." % expiry_raw,
            )
        else:
            days = (expires - self.now()).days
            add(
                "product_expiry",
                "This version is supported for long enough",
                "passed" if days >= minimum else "failed",
                "high",
                "protection",
                "Expires %s, in %s." % (expires.date().isoformat(), plural(days, "day")),
                metrics={"days_to_expiry": days},
                expected="at least %s days" % minimum,
                remediation=None if days >= minimum else "Each version expires nine months after release: deploy a newer one.",
                docs=DOCS["releases"],
            )

    def now(self):
        stamp = self.data.get("now")
        moment = datetime.datetime.fromtimestamp(stamp, UTC) if stamp else datetime.datetime.now(UTC)
        return moment.replace(tzinfo=None)

    def eicar(self, level):
        add = self.suite.add
        action = self.actions.get("eicar") or {}
        name = "The antivirus detects the EICAR test file"
        if not action.get("ran"):
            add("eicar_detection", name, "skipped", "critical", "protection", action.get("reason") or "Not run.")
            return
        mode = action.get("mode")
        threat = action.get("threat") or {}
        seconds = action.get("seconds")
        metrics = {"detection_seconds": seconds} if action.get("detected") and seconds is not None else None
        if action.get("failed"):
            add("eicar_detection", name, "error", "critical", "protection", "The test could not run: %s" % action.get("msg"))
        elif mode == "real_time":
            ok = action.get("removed") and action.get("detected")
            detail = (
                "Detected as %s and removed in %.2f s." % (threat.get("name"), seconds)
                if ok
                else "Removed in %.2f s, but not in the threat history." % seconds
                if action.get("removed")
                else "Not removed within %s s." % self.settings.get("eicar_timeout", 120)
            )
            add(
                "eicar_detection",
                name,
                "passed" if ok else "failed",
                "critical",
                "protection",
                detail,
                metrics=metrics,
                remediation=None if ok else "Check real_time_protection_available, and exclusions covering %s." % action.get("directory"),
            )
        elif mode == "audit":
            ok = action.get("detected")
            add(
                "eicar_detection",
                name,
                "passed" if ok else "failed",
                "critical",
                "protection",
                "Detected as %s in %.2f s (audit mode leaves the file)." % (threat.get("name"), seconds)
                if ok
                else "Not detected within %s s." % self.settings.get("eicar_timeout", 120),
                metrics=metrics,
            )
        else:
            if action.get("scan_rc") not in (0, None) and not self.licensed and "No scan is running" in (action.get("scan_output") or ""):
                add(
                    "eicar_detection",
                    name,
                    "skipped",
                    "critical",
                    "protection",
                    "At enforcement level %s the test needs an on-demand scan, which mdatp runs only on an onboarded device." % level,
                )
                return
            ok = action.get("detected")
            add(
                "eicar_detection",
                name,
                "passed" if ok else "failed",
                "critical",
                "protection",
                "Detected as %s by a custom scan in %.2f s." % (threat.get("name"), seconds)
                if ok
                else "A custom scan did not detect it: %s" % (action.get("scan_output") or "no output"),
                metrics=metrics,
            )

    def quick_scan(self):
        add = self.suite.add
        action = self.actions.get("quick_scan") or {}
        name = "A quick scan completes"
        if not action.get("ran"):
            add("quick_scan", name, "skipped", "high", "protection", action.get("reason") or "Not run.")
            return
        output = action_output(action)
        if action.get("rc") != 0 and not self.licensed and "No scan is running" in output:
            add(
                "quick_scan",
                name,
                "skipped",
                "high",
                "protection",
                'mdatp runs on-demand scans only on an onboarded device (it answers "No scan is running").',
            )
            return
        if action.get("timed_out"):
            add(
                "quick_scan",
                name,
                "failed",
                "high",
                "protection",
                "Still running after %s s, so it was cancelled." % action.get("timeout"),
                metrics={"duration_seconds": action.get("seconds")},
                docs=DOCS["performance"],
            )
            return
        files = self.detail_field("antivirus", "last_on_demand_scan_files_scanned")
        threats = self.detail_field("antivirus", "last_on_demand_scan_threat_count")
        metrics = {"duration_seconds": action.get("seconds")}
        if isinstance(files, int):
            metrics["files_scanned"] = files
        if isinstance(threats, int):
            metrics["threats"] = threats
        ok = action.get("rc") == 0
        add(
            "quick_scan",
            name,
            "passed" if ok else "failed",
            "high",
            "protection",
            "Completed in %.0f s%s." % (action.get("seconds") or 0, (", %s files" % files) if isinstance(files, int) else "")
            if ok
            else "mdatp scan quick exited %s." % action.get("rc"),
            metrics=metrics,
            output=None if ok else output[-2000:],
            docs=DOCS["performance"],
        )

    def definitions(self):
        add = self.suite.add
        health = self.health
        status = health.get("definitions_status") or self.detail_field("definitions", "definitions_status")
        version = health.get("definitions_version")
        action = self.actions.get("definitions_update") or {}
        if action.get("ran"):
            output = action_output(action)
            ok = action.get("rc") == 0 and status == "up_to_date"
            if ok:
                if "is up to date" in output:
                    detail = "Already up to date at %s." % version
                else:
                    detail = "Updated to %s in %.0f s." % (version, action.get("seconds") or 0)
            elif action.get("timed_out"):
                detail = "Still updating after %s s." % self.settings.get("definitions_timeout", 600)
            else:
                reason = self.detail_field("definitions", "definitions_update_fail_reason")
                detail = "mdatp definitions update exited %s; status %s%s." % (action.get("rc"), status, ("; " + reason) if reason else "")
            add(
                "definitions_update",
                "Security intelligence updates from Microsoft",
                "passed" if ok else "failed",
                "high",
                "protection",
                detail,
                metrics={"duration_seconds": action.get("seconds")} if action.get("seconds") is not None else None,
                output=None if ok else output[-2000:],
                docs=DOCS["connectivity"],
            )
        else:
            add(
                "definitions_update",
                "Security intelligence updates from Microsoft",
                "skipped",
                "high",
                "protection",
                action.get("reason") or "Not run.",
                docs=DOCS["offline_updates"] if not self.online else None,
            )

        if not self.online:
            add(
                "definitions_current",
                "Security intelligence is up to date",
                "skipped",
                "high",
                "protection",
                "The host is offline (mde_linux_checks_online is false): its security intelligence is what the package shipped (%s) "
                "unless an offline update mirror serves it." % version,
                docs=DOCS["offline_updates"],
            )
            return
        minutes = health.get("definitions_updated_minutes_ago")
        limit = float(self.settings.get("max_definitions_age_hours", 48))
        if status is None and minutes is None:
            add(
                "definitions_current",
                "Security intelligence is up to date",
                "error",
                "high",
                "protection",
                "mdatp reports no definitions status.",
            )
            return
        age_ok = isinstance(minutes, int) and minutes <= limit * 60
        ok = status == "up_to_date" and age_ok
        add(
            "definitions_current",
            "Security intelligence is up to date",
            "passed" if ok else "failed",
            "high",
            "protection",
            "Status %s, version %s, updated %s ago."
            % (status, version, ("%.1f h" % (minutes / 60.0)) if isinstance(minutes, int) else "an unknown time"),
            metrics={"age_hours": round(minutes / 60.0, 2)} if isinstance(minutes, int) else None,
            expected="up_to_date, at most %g h old" % limit,
            docs=DOCS["connectivity"],
        )

    # --- Configuration ---------------------------------------------------------------------------

    def configuration(self):
        add = self.suite.add
        managed = self.after.get("managed") or {}
        if not managed.get("present"):
            add(
                "managed_config_valid",
                "mdatp_managed.json is valid JSON",
                "skipped",
                "high",
                "configuration",
                "There is no managed configuration (%s)." % managed.get("path", "mdatp_managed.json"),
            )
            add(
                "managed_config_applied",
                "The agent applies mdatp_managed.json",
                "skipped",
                "high",
                "configuration",
                "There is no managed configuration.",
            )
        elif not managed.get("valid"):
            add(
                "managed_config_valid",
                "mdatp_managed.json is valid JSON",
                "failed",
                "critical",
                "configuration",
                "It does not parse: %s. mdatp ignores the whole file, so every managed setting reverts to its default."
                % managed.get("error"),
                docs=DOCS["preferences"],
            )
            add(
                "managed_config_applied",
                "The agent applies mdatp_managed.json",
                "skipped",
                "high",
                "configuration",
                "The file does not parse.",
            )
        else:
            add(
                "managed_config_valid",
                "mdatp_managed.json is valid JSON",
                "passed",
                "high",
                "configuration",
                "Valid, with %s." % listing(sorted(managed.get("content") or {})) if managed.get("content") else "Valid.",
            )
            content = managed.get("content") or {}
            wanted = set(f for path, fields in MANAGED_FIELDS if nested(content, path) is not None for f in fields)
            if nested(content, ("antivirusEngine", "enforcementLevel")) is not None and "antivirus_enforcement_level" in self.health:
                wanted.add("antivirus_enforcement_level")  # from 101.26052.0012
            wanted = sorted(wanted)
            if not wanted:
                add(
                    "managed_config_applied",
                    "The agent applies mdatp_managed.json",
                    "skipped",
                    "high",
                    "configuration",
                    "It sets none of the settings mdatp marks [managed] in its health output.",
                )
            else:
                missing = [f for f in wanted if f not in self.managed_fields]
                add(
                    "managed_config_applied",
                    "The agent applies mdatp_managed.json",
                    "passed" if not missing else "failed",
                    "high",
                    "configuration",
                    "mdatp shows %s as managed." % listing(wanted)
                    if not missing
                    else "Set in the file, but not shown as managed: %s." % listing(missing),
                    docs=DOCS["preferences"],
                )

        for field, expected in sorted((self.settings.get("expected_health") or {}).items()):
            actual = self.health.get(field)
            accepted = expected if isinstance(expected, list) else [expected]
            if field not in self.health:
                add(
                    "health.%s" % field,
                    "mdatp health reports %s as expected" % field,
                    "failed",
                    "high",
                    "configuration",
                    "mdatp does not report %s." % field,
                    expected=" or ".join(str(a) for a in accepted),
                )
                continue
            ok = actual in accepted
            add(
                "health.%s" % field,
                "mdatp health reports %s as expected" % field,
                "passed" if ok else "failed",
                "high",
                "configuration",
                "%s: %s%s." % (field, actual, " [managed]" if field in self.managed_fields else ""),
                expected=" or ".join(str(a) for a in accepted),
                actual=str(actual),
                docs=DOCS["health"],
            )

    # --- Onboarding ------------------------------------------------------------------------------

    def onboarding(self):
        add = self.suite.add
        health = self.health
        expect = self.expect_onboarded()
        issues = health.get("health_issues") if isinstance(health.get("health_issues"), list) else []
        if not expect:
            add(
                "onboarded",
                "The device is onboarded to Defender for Endpoint",
                "skipped",
                "critical",
                "onboarding",
                "Not expected to be onboarded: no onboarding package on the host%s."
                % (" and mde_linux_checks_onboarded is false" if str(self.settings.get("onboarded")).lower() == "false" else ""),
            )
        else:
            add(
                "onboarded",
                "The device is onboarded to Defender for Endpoint",
                "passed" if self.licensed else "failed",
                "critical",
                "onboarding",
                "Licensed, organisation %s." % health.get("org_id")
                if self.licensed
                else "Not licensed: %s." % (listing(issues) or "no reason given"),
                remediation=None
                if self.licensed
                else "Check the onboarding package is for this tenant and the device can reach Defender's cloud (mdatp connectivity test).",
                docs=DOCS["connectivity"],
            )

        org = self.settings.get("expected_org_id") or ""
        if not org:
            add(
                "organisation",
                "The device is onboarded to the expected organisation",
                "skipped",
                "critical",
                "onboarding",
                "No expected organisation given (mde_linux_checks_expected_org_id).",
            )
        elif not self.licensed:
            add(
                "organisation",
                "The device is onboarded to the expected organisation",
                "skipped" if not expect else "failed",
                "critical",
                "onboarding",
                "The device is not onboarded.",
            )
        else:
            actual = health.get("org_id")
            add(
                "organisation",
                "The device is onboarded to the expected organisation",
                "passed" if actual == org else "failed",
                "critical",
                "onboarding",
                "Organisation %s." % actual,
                expected=org,
                actual=actual,
            )

        if self.licensed:
            healthy = health.get("healthy") is True
            add(
                "healthy",
                "Defender reports itself healthy",
                "passed" if healthy else "failed",
                "critical",
                "onboarding",
                "Healthy." if healthy else "Not healthy: %s." % (listing(issues) or "no issues listed"),
                docs=DOCS["health"],
            )
        else:
            add(
                "healthy",
                "Defender reports itself healthy",
                "skipped",
                "critical",
                "onboarding",
                "A device that is not onboarded never reports healthy.",
            )

        unexpected = [i for i in issues if not (not self.licensed and not expect and i in NOT_ONBOARDED_ISSUES)]
        tolerated = [i for i in issues if i not in unexpected]
        add(
            "health_issues",
            "Defender reports no health issues",
            "passed" if not unexpected else "failed",
            "high",
            "onboarding",
            (
                "None."
                if not tolerated
                else "Only %s, as expected on a device that is not onboarded." % listing('"%s"' % i for i in tolerated)
            )
            if not unexpected
            else "%s." % listing('"%s"' % i for i in unexpected),
            docs=DOCS["health"],
        )

        edr_id = health.get("edr_machine_id")
        add(
            "edr_identity",
            "The device has an EDR identity",
            "passed" if edr_id else "failed",
            "high",
            "onboarding",
            "edr_machine_id %s." % edr_id if edr_id else "No edr_machine_id.",
        )

        fleet = self.data.get("fleet") or {}
        me = self.data.get("host")
        if len(fleet) < 2:
            add(
                "unique_identity",
                "No other host in the run shares this device's identity",
                "skipped",
                "critical",
                "onboarding",
                "Only one host in this run, so there is nothing to compare.",
            )
        else:
            clashes = []
            for field in ("machine_guid", "edr_machine_id"):
                mine = health.get(field)
                others = sorted(h for h, ids in fleet.items() if h != me and mine and (ids or {}).get(field) == mine)
                if others:
                    clashes.append("%s %s is also on %s" % (field, mine, listing(others)))
            add(
                "unique_identity",
                "No other host in the run shares this device's identity",
                "passed" if not clashes else "failed",
                "critical",
                "onboarding",
                "Unique among %s." % plural(len(fleet), "host") if not clashes else "; ".join(clashes) + ".",
                remediation=None
                if not clashes
                else "Hosts cloned from an image that had Defender installed share identities: remove "
                "the identity from the image (101.25072.0003 and later fix clones).",
                docs=None if not clashes else DOCS["releases"],
            )

        action = self.actions.get("connectivity") or {}
        if not action.get("ran"):
            add(
                "cloud_connectivity",
                "Defender's cloud services are reachable",
                "skipped",
                "high",
                "onboarding",
                action.get("reason") or "Not run.",
            )
        else:
            lines = action_output(action).splitlines()
            tested = [line for line in lines if line.startswith("Testing connection with")]
            failed = [line for line in tested if not line.rstrip().endswith("[OK]")]
            ok = action.get("rc") == 0 and tested and not failed
            add(
                "cloud_connectivity",
                "Defender's cloud services are reachable",
                "passed" if ok else "failed",
                "high",
                "onboarding",
                "%s reachable in %.0f s%s."
                % (
                    plural(len(tested), "URL"),
                    action.get("seconds") or 0,
                    "".join(", " + line.strip().rstrip(".").lower() for line in lines if line.startswith("Proxy detected")),
                )
                if ok
                else "%s of %s failed%s."
                % (len(failed), plural(len(tested), "URL"), "" if tested else " (no URLs tested, exit %s)" % action.get("rc")),
                output="\n".join(failed)[-4000:] if failed else None,
                metrics={"urls_tested": len(tested), "urls_failed": len(failed), "duration_seconds": action.get("seconds")},
                docs=DOCS["connectivity"],
            )

    # --- The system ------------------------------------------------------------------------------

    def system(self):
        add = self.suite.add
        system = self.after.get("system") or {}
        before = self.before.get("system") or {}
        if "error" in system:
            add("system_requirements", "The host meets Microsoft's minimum requirements", "error", "high", "system", system["error"])
            return
        cpus, memory = system.get("cpus") or 0, system.get("memory_total_mib") or 0
        ok = cpus >= 1 and memory >= 870
        add(
            "system_requirements",
            "The host meets Microsoft's minimum requirements",
            "passed" if ok else "failed",
            "high",
            "system",
            "%s, %.0f MiB of memory." % (plural(cpus, "CPU"), memory),
            expected="1 CPU and 1 GiB of memory (870 MiB after the kernel's share)",
            metrics={"cpus": cpus, "memory_total_mib": memory},
            docs=DOCS["prerequisites"],
        )

        free = system.get("free_mib") or {}
        sizes = system.get("defender_disk_mib") or {}
        install, data = sizes.get("/opt/microsoft/mdatp") or 0, sizes.get("/var/opt/microsoft/mdatp") or 0
        problems = []
        if self.installed:
            need_opt, need_var = round(install * 1.2), round(data * 2)
            name = "There is room for the next update"
            what_opt, what_var = "the next platform update", "a security intelligence update"
            passed = "/opt %.0f MiB free (the install is %.0f MiB), /var %.0f MiB free (Defender's data is %.0f MiB)." % (
                free.get("/opt") or 0,
                install,
                free.get("/var") or 0,
                data,
            )
        else:
            # 101.26101.0000 installs 432 MiB in /opt and keeps about 200 MiB in /var, with room to update.
            need_opt, need_var = 600, 400
            name = "There is room to install Defender"
            what_opt, what_var = "the install", "Defender's data"
            passed = "/opt %.0f MiB free and /var %.0f MiB free, enough to install it." % (free.get("/opt") or 0, free.get("/var") or 0)
        if free.get("/opt") is not None and free["/opt"] < need_opt:
            problems.append("/opt has %.0f MiB free, %s needs about %d" % (free["/opt"], what_opt, need_opt))
        if free.get("/var") is not None and free["/var"] < need_var:
            problems.append("/var has %.0f MiB free, %s needs about %d" % (free["/var"], what_var, need_var))
        add(
            "disk_space_for_updates",
            name,
            "passed" if not problems else "failed",
            "high",
            "system",
            passed if not problems else "; ".join(problems) + ".",
            metrics={
                "free_opt_mib": free.get("/opt") or 0,
                "free_var_mib": free.get("/var") or 0,
                "install_mib": install,
                "data_mib": data,
            },
            remediation=None
            if not problems
            else "An update unpacks the new version beside the old one before removing it: free space, or it fails part way.",
        )

        filesystems = system.get("filesystems") or {}
        unsupported = ["%s (%s)" % (path, fs) for path, fs in sorted(filesystems.items()) if fs and fs not in RTP_FILESYSTEMS]
        add(
            "filesystems_supported",
            "Real-time protection supports the host's file systems",
            "passed" if not unsupported else "failed",
            "medium",
            "system",
            "%s." % listing("%s %s" % (p, fs) for p, fs in sorted(filesystems.items()) if fs)
            if not unsupported
            else "Not watched by real-time protection: %s." % listing(unsupported),
            docs=DOCS["prerequisites"],
        )

        synced = system.get("time_synchronised")
        if synced is None:
            add("time_synchronised", "The clock is synchronised", "skipped", "medium", "system", "timedatectl is not available.")
        else:
            add(
                "time_synchronised",
                "The clock is synchronised",
                "passed" if synced else "failed",
                "medium",
                "system",
                "NTP synchronised."
                if synced
                else "Not synchronised: certificate checks against Defender's cloud fail when the clock drifts.",
            )

        selinux = system.get("selinux") or {}
        if selinux.get("mode") in (None, "disabled"):
            for check_id, name in (
                ("selinux_policy", "Defender's SELinux policy is loaded"),
                ("selinux_denials", "SELinux has denied Defender nothing recently"),
            ):
                add(
                    check_id,
                    name,
                    "skipped",
                    "high" if check_id == "selinux_denials" else "medium",
                    "system",
                    "SELinux is disabled or absent.",
                )
        else:
            modules = selinux.get("modules")
            if modules is None:
                add(
                    "selinux_policy",
                    "Defender's SELinux policy is loaded",
                    "error",
                    "medium",
                    "system",
                    "Could not list the SELinux modules.",
                )
            else:
                add(
                    "selinux_policy",
                    "Defender's SELinux policy is loaded",
                    "passed" if modules else "failed",
                    "medium",
                    "system",
                    "Modules: %s." % listing(modules) if modules else "No Defender SELinux module is loaded.",
                    remediation=None if modules else "Reinstall mdatp: 101.26032.0000 fixed upgrades removing its SELinux modules.",
                    docs=None if modules else DOCS["releases"],
                )
            denials = get(self.after, "logs", "avc_denials") or {}
            denials_after_reboot = get(self.rebooted or {}, "logs", "avc_denials") or {}
            count = (denials.get("count") or 0) + (denials_after_reboot.get("count") or 0)
            add(
                "selinux_denials",
                "SELinux has denied Defender nothing recently",
                "passed" if not count else "failed",
                "high",
                "system",
                "No denials %s (SELinux %s)." % (self.window, selinux.get("mode"))
                if not count
                else "%s %s." % (plural(count, "denial"), self.window),
                output="\n".join((denials.get("lines") or []) + (denials_after_reboot.get("lines") or [])) or None,
                metrics={"denials": count},
            )
        old_mode = get(before, "selinux", "mode")
        if not old_mode or old_mode == "disabled" and selinux.get("mode") in (None, "disabled"):
            add("selinux_mode_unchanged", "The SELinux mode did not change", "skipped", "high", "system", "SELinux is disabled or absent.")
        else:
            same = old_mode == selinux.get("mode")
            add(
                "selinux_mode_unchanged",
                "The SELinux mode did not change",
                "passed" if same else "failed",
                "high",
                "system",
                "Still %s." % old_mode if same else "Changed from %s to %s during the checks." % (old_mode, selinux.get("mode")),
                remediation=None if same else "Something during the checks or the install changed SELinux: find it before rolling out.",
            )

    # --- Resources --------------------------------------------------------------------------------

    def resources(self):
        add = self.suite.add
        processes = self.after.get("processes") or {}
        found = processes.get("processes") or []
        if "error" in processes or not found:
            add(
                "resource_usage",
                "Defender's memory and CPU use was measured",
                "error",
                "medium",
                "performance",
                processes.get("error") or "No Defender processes are running.",
            )
            return
        metrics = {"memory_mib": processes.get("memory_mib"), "processes": len(found)}
        if processes.get("cpu_percent") is not None:
            metrics["cpu_percent"] = processes["cpu_percent"]
        roles = sorted(set(p.get("role") for p in found))
        add(
            "resource_usage",
            "Defender's memory and CPU use was measured",
            "passed",
            "medium",
            "performance",
            "%s (%s): %.0f MiB resident%s."
            % (
                plural(len(found), "process", "processes"),
                ", ".join(roles),
                processes.get("memory_mib") or 0,
                (", %.1f%% CPU over %g s" % (processes["cpu_percent"], processes.get("sample_seconds")))
                if processes.get("cpu_percent") is not None
                else "",
            ),
            metrics=metrics,
            docs=DOCS["performance"],
        )
        sizes = get(self.after, "system", "defender_disk_mib") or {}
        add(
            "disk_usage",
            "Defender's disk use was measured",
            "passed",
            "info",
            "performance",
            "Install %.0f MiB, data %.0f MiB, logs %.0f MiB."
            % (
                sizes.get("/opt/microsoft/mdatp") or 0,
                sizes.get("/var/opt/microsoft/mdatp") or 0,
                sizes.get("/var/log/microsoft/mdatp") or 0,
            ),
            metrics={
                "install_mib": sizes.get("/opt/microsoft/mdatp") or 0,
                "data_mib": sizes.get("/var/opt/microsoft/mdatp") or 0,
                "logs_mib": sizes.get("/var/log/microsoft/mdatp") or 0,
            },
        )

    # --- Reboot -----------------------------------------------------------------------------------

    def reboot(self):
        add = self.suite.add
        action = self.actions.get("reboot") or {}
        name = "Defender comes back after a reboot"
        if not action.get("ran"):
            add("service_survives_reboot", name, "skipped", "critical", "stability", action.get("reason") or "Not run.")
            return
        if action.get("failed") or not self.rebooted:
            add(
                "service_survives_reboot",
                name,
                "error",
                "critical",
                "stability",
                "The reboot failed: %s" % (action.get("msg") or "no answer"),
            )
            return
        problems = []
        if get(self.rebooted, "system", "boot_id") == get(self.after, "system", "boot_id"):
            problems.append("the boot id did not change, so the host did not reboot")
        service = self.rebooted.get("service") or {}
        if service.get("ActiveState") != "active":
            problems.append("mdatp is %s" % service.get("ActiveState"))
        if service.get("UnitFileState") != "enabled":
            problems.append("the unit is %s" % service.get("UnitFileState"))
        health = get(self.rebooted, "mdatp", "health") or {}
        settle = self.actions.get("settle_after_reboot") or {}
        if health.get("engine_load_status") != ENGINE_LOADED:
            problems.append("the engine is not loaded (%s)" % health.get("engine_load_status"))
        level, _ = self.enforcement_level()
        if level in ("real_time", "audit") and health.get("real_time_protection_available") is not True:
            problems.append("real-time protection is not available")
        before_issues = set(self.health.get("health_issues") or [])
        new_issues = sorted(set(health.get("health_issues") or []) - before_issues)
        if new_issues:
            problems.append("new health issues: %s" % listing(new_issues))
        # The reboot module's own elapsed time is not the outage: time it from the probes' clocks,
        # from the end of the probe before the reboot to the start of the one after it.
        back = None
        if self.rebooted.get("taken_at") and (self.after.get("finished_at") or self.after.get("taken_at")):
            back = round(self.rebooted["taken_at"] - (self.after.get("finished_at") or self.after["taken_at"]), 1)
        metrics = {"seconds_until_reachable": back} if back is not None else {}
        if settle.get("seconds") is not None:
            metrics["seconds_to_load_after_reboot"] = settle["seconds"]
        add(
            "service_survives_reboot",
            name,
            "passed" if not problems else "failed",
            "critical",
            "stability",
            "Back in %.0f s: running, enabled, engine loaded%s."
            % (back or 0, ", real-time protection available" if level in ("real_time", "audit") else "")
            if not problems
            else "After the reboot " + "; ".join(problems) + ".",
            metrics=metrics,
            remediation=None
            if not problems
            else "Versions 101.26042.0000 to 0009 could leave the service disabled after an upgrade and reboot.",
            docs=None if not problems else DOCS["releases"],
        )

    # --- Upgrade ----------------------------------------------------------------------------------

    def upgrade(self):
        add = self.suite.add
        base = self.baseline
        if not base:
            add(
                "upgrade_compared",
                "The host was compared with its snapshot from before the upgrade",
                "skipped",
                "high",
                "upgrade",
                "No snapshot from before an upgrade (mde_linux_checks_compare_to), so there is nothing to compare.",
            )
            return
        if base.get("schema") == "missing":
            add(
                "upgrade_compared",
                "The host was compared with its snapshot from before the upgrade",
                "error",
                "high",
                "upgrade",
                "The snapshot %s does not exist: take it with mde_linux_checks_snapshot_to before the upgrade." % base.get("path"),
            )
            return
        if base.get("schema") != BASELINE_SCHEMA:
            add(
                "upgrade_compared",
                "The host was compared with its snapshot from before the upgrade",
                "error",
                "high",
                "upgrade",
                "The snapshot is not a %s file." % BASELINE_SCHEMA,
            )
            return
        old_health = base.get("health") or {}
        old_version, new_version = base.get("version"), get(self.after, "mdatp", "version")
        taken = (
            datetime.datetime.fromtimestamp(base["taken_at"], UTC).strftime("%Y-%m-%d %H:%M UTC")
            if base.get("taken_at")
            else "an unknown time"
        )
        add(
            "upgrade_compared",
            "The host was compared with its snapshot from before the upgrade",
            "passed",
            "high",
            "upgrade",
            "Compared with the snapshot of %s at %s, taken %s." % (base.get("host") or "this host", old_version, taken),
        )
        if version_tuple(new_version) > version_tuple(old_version):
            add(
                "upgrade_version",
                "The upgrade installed a newer version",
                "passed",
                "critical",
                "upgrade",
                "%s to %s." % (old_version, new_version),
            )
        else:
            add(
                "upgrade_version",
                "The upgrade installed a newer version",
                "failed",
                "critical",
                "upgrade",
                "%s to %s: %s." % (old_version, new_version, "nothing was upgraded" if new_version == old_version else "a downgrade"),
            )

        changed = [
            "%s %s to %s" % (f, old_health.get(f) or "(none)", self.health.get(f) or "(none)")
            for f in IDENTITY_FIELDS
            if old_health.get(f) != self.health.get(f) and (old_health.get(f) or self.health.get(f))
        ]
        add(
            "upgrade_identity",
            "The upgrade kept the device's identity",
            "passed" if not changed else "failed",
            "critical",
            "upgrade",
            "machine_guid, edr_machine_id and org_id unchanged." if not changed else "; ".join(changed) + ".",
            remediation=None if not changed else "A new identity shows as a second device in the portal, and the old one goes inactive.",
        )

        preserved = self.settings.get("preserved_fields") or []
        moved = []
        for field in preserved:
            if field in old_health and old_health.get(field) != self.health.get(field):
                moved.append("%s %s to %s" % (field, old_health.get(field), self.health.get(field)))
            if field in (base.get("managed_fields") or []) and field not in self.managed_fields:
                moved.append("%s is no longer [managed]" % field)
        add(
            "upgrade_settings",
            "The upgrade kept the protection settings",
            "passed" if not moved else "failed",
            "high",
            "upgrade",
            "%s unchanged." % plural(len([f for f in preserved if f in old_health]), "setting") if not moved else "; ".join(moved) + ".",
        )

        old_exclusions = get(base, "exclusions")
        new_exclusions = get(self.after, "mdatp", "exclusions")
        if old_exclusions is None or new_exclusions is None:
            add(
                "upgrade_exclusions",
                "The upgrade kept the antivirus exclusions",
                "skipped",
                "high",
                "upgrade",
                "The exclusions could not be read %s." % ("before" if old_exclusions is None else "after"),
            )
        else:
            same = old_exclusions == new_exclusions
            count = len((new_exclusions or {}).get("exclusions") or [])
            add(
                "upgrade_exclusions",
                "The upgrade kept the antivirus exclusions",
                "passed" if same else "failed",
                "high",
                "upgrade",
                "%s, unchanged." % plural(count, "exclusion") if same else "The exclusions changed.",
                docs=DOCS["exclusions"],
            )

        removed = sorted(set(old_health) - set(self.health))
        added = sorted(set(self.health) - set(old_health))
        add(
            "upgrade_health_fields",
            "mdatp health still reports every field it did",
            "passed" if not removed else "failed",
            "medium",
            "upgrade",
            ("No field removed%s." % ("; new: %s" % listing(added) if added else ""))
            if not removed
            else "Removed: %s%s." % (listing(removed), "; new: %s" % listing(added) if added else ""),
            remediation=None if not removed else "Scripts and monitoring that read the removed fields will break.",
            metrics={"fields_removed": len(removed), "fields_added": len(added)},
        )

        old_defs, new_defs = old_health.get("definitions_version"), self.health.get("definitions_version")
        if old_defs and new_defs:
            ok = version_tuple(new_defs) >= version_tuple(old_defs)
            add(
                "upgrade_definitions",
                "The upgrade kept the security intelligence",
                "passed" if ok else "failed",
                "medium",
                "upgrade",
                "%s to %s." % (old_defs, new_defs),
                remediation=None if ok else "The upgrade rolled the security intelligence back to the package's own.",
            )

        old_requires = set(get(base, "package", "requires") or [])
        new_requires = set(get(self.after, "package", "requires") or [])
        added_deps, removed_deps = sorted(new_requires - old_requires), sorted(old_requires - new_requires)
        add(
            "upgrade_dependencies",
            "The upgrade needs no new dependencies",
            "passed" if not added_deps else "failed",
            "info",
            "upgrade",
            "No new dependencies%s." % ("; dropped %s" % listing(removed_deps) if removed_deps else "")
            if not added_deps
            else "New: %s%s." % (listing(added_deps), "; dropped %s" % listing(removed_deps) if removed_deps else ""),
            remediation=None
            if not added_deps
            else "Hosts without repositories (offline, or a Satellite content view without them) need these too.",
        )

        old_memory = get(base, "metrics", "memory_mib")
        new_memory = get(self.after, "processes", "memory_mib")
        if old_memory and new_memory is not None:
            change = round((new_memory - old_memory) / old_memory * 100, 1)
            add(
                "upgrade_resources",
                "The upgrade's memory use was compared",
                "passed",
                "info",
                "upgrade",
                "Memory %.0f MiB to %.0f MiB (%+.1f%%)." % (old_memory, new_memory, change),
                metrics={"memory_mib_before": old_memory, "memory_mib": new_memory, "memory_change_percent": change},
            )


def properties(data, checks):
    after = (data.get("probes") or {}).get("after") or {}
    health = get(after, "mdatp", "health") or {}
    package = (get(after, "package", "installed") or [{}])[0]
    system = after.get("system") or {}
    evaluation = Evaluation(data)
    level, _ = evaluation.enforcement_level()
    result = {
        "app_version": health.get("app_version") or get(after, "mdatp", "version"),
        "package": "%s-%s.%s" % (package.get("version"), package.get("release"), package.get("arch")) if package else None,
        "engine_version": health.get("engine_version") or evaluation.detail_field("engine", "engine_version"),
        "definitions_version": health.get("definitions_version"),
        "release_ring": health.get("release_ring"),
        "enforcement_level": level,
        "onboarded": health.get("licensed"),
        "org_id": health.get("org_id") or None,
        "supplementary_events_subsystem": health.get("supplementary_events_subsystem"),
        "kernel": system.get("kernel"),
        "selinux": get(system, "selinux", "mode"),
        "fips_enabled": system.get("fips_enabled"),
        "profile": (data.get("settings") or {}).get("profile"),
        "online": (data.get("settings") or {}).get("online"),
    }
    return dict((k, v) for k, v in result.items() if v not in (None, ""))


def mde_linux_checks_suite(data):
    """The test results for one host, from the probes and actions the role gathered."""
    checks = Evaluation(data).run()
    return {
        "schema": SUITE_SCHEMA,
        "suite": "mde_linux_checks",
        "name": "Microsoft Defender for Endpoint on Linux",
        "started": data.get("started"),
        "finished": data.get("finished"),
        "properties": properties(data, checks),
        "checks": checks,
    }


def mde_linux_checks_baseline(probe, host):
    """What to keep from before an upgrade, to compare with after it."""
    mdatp = probe.get("mdatp") or {}
    return {
        "schema": BASELINE_SCHEMA,
        "host": host,
        "taken_at": probe.get("taken_at"),
        "version": mdatp.get("version"),
        "health": mdatp.get("health") or {},
        "managed_fields": mdatp.get("managed_fields") or [],
        "features": get(mdatp, "details", "features", "fields") or {},
        "exclusions": mdatp.get("exclusions"),
        "package": {"installed": get(probe, "package", "installed") or [], "requires": get(probe, "package", "requires") or []},
        "metrics": {"memory_mib": get(probe, "processes", "memory_mib"), "cpu_percent": get(probe, "processes", "cpu_percent")},
    }


def mde_linux_checks_enforcement_level(probe):
    """The level the antivirus runs at, as the EICAR test needs to know before it runs."""
    level, _ = Evaluation({"probes": {"after": probe or {}}}).enforcement_level()
    return level


def mde_linux_checks_seconds(delta):
    """A command result's delta ("0:01:02.345678") in seconds."""
    match = re.match(r"^(?:(\d+) days?, )?(\d+):(\d\d):(\d\d(?:\.\d+)?)$", str(delta or "").strip())
    if not match:
        return None
    days, hours, minutes, seconds = match.groups()
    return round(int(days or 0) * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds), 3)


def mde_linux_checks_failed(suite):
    """Whether any check failed or errored, for collecting diagnostics on failure."""
    return any(c.get("status") in ("failed", "error") and c.get("severity") != "info" for c in (suite or {}).get("checks") or [])


class FilterModule(object):
    def filters(self):
        return {
            "mde_linux_checks_suite": mde_linux_checks_suite,
            "mde_linux_checks_baseline": mde_linux_checks_baseline,
            "mde_linux_checks_failed": mde_linux_checks_failed,
            "mde_linux_checks_enforcement_level": mde_linux_checks_enforcement_level,
            "mde_linux_checks_seconds": mde_linux_checks_seconds,
        }
