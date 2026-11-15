"""Unit tests for the judgement (filter_plugins/mde_linux_checks.py) and the probe's parsers.

The starting point is a real probe of a RHEL 9.8 Azure VM running mdatp 101.26101.0000, online
but not onboarded (tests/unit/fixtures/rhel9-online-unlicensed.json, its device ids replaced with
made-up ones). Each test changes what it needs, so every check is shown passing on real data and
failing for the reason it exists. Every suite is validated against libre_devops.test_results/v1.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checks = load("mde_linux_checks", ROOT / "filter_plugins" / "mde_linux_checks.py")
probe_module = load("mde_linux_checks_probe", ROOT / "library" / "mde_linux_checks_probe.py")

# A copy of libre_devops.test_results_report's published contract for checks roles.
SUITE_SCHEMA = json.loads((FIXTURES / "test-results.schema.json").read_text())
REAL = json.loads((FIXTURES / "rhel9-online-unlicensed.json").read_text())
NOW = REAL["taken_at"]


def settings(**extra):
    base = {
        "profile": "release",
        "online": True,
        "onboarded": "auto",
        "expected_version": "",
        "expected_org_id": "",
        "expected_enforcement_level": "real_time",
        "expected_health": {},
        "skip": [],
        "min_days_to_expiry": 30,
        "max_definitions_age_hours": 48,
        "eicar_timeout": 60,
        "preserved_fields": ["antivirus_enforcement_level", "real_time_protection_enabled", "release_ring"],
    }
    base.update(extra)
    return base


def actions(**extra):
    base = {
        "settle": {"seconds": 0.1, "loaded": True},
        "eicar": {
            "ran": True,
            "mode": "real_time",
            "detected": True,
            "removed": True,
            "seconds": 0.35,
            "threat": {"name": "Virus:DOS/EICAR_Test_File", "id": "t1"},
        },
        "quick_scan": {
            "ran": True,
            "rc": 2,
            "stdout": "ATTENTION: No license found. Contact your administrator for help.\nNo scan is running",
        },
        "definitions_update": {"ran": True, "rc": 0, "stdout": "Security intelligence is up to date", "seconds": 0.2},
        "connectivity": {
            "ran": True,
            "rc": 0,
            "seconds": 18.2,
            "stdout": "\n".join(
                [
                    "Testing connection with https://a.example ... [OK]",
                    "Testing connection with https://b.example ... [OK]",
                    "Proxy detected: NO",
                ]
            ),
        },
        "reboot": {"ran": False, "reason": "Not run: mde_linux_checks_reboot is false."},
    }
    base.update(extra)
    return base


def suite(after=None, before=None, rebooted=None, settings_=None, actions_=None, baseline=None, fleet=None):
    after = after or copy.deepcopy(REAL)
    data = {
        "host": "vm1",
        "now": NOW,
        "started": "2026-11-15T21:00:00Z",
        "finished": "2026-11-15T21:05:00Z",
        "probes": {"before": before or copy.deepcopy(REAL), "after": after, "rebooted": rebooted},
        "actions": actions_ or actions(),
        "settings": settings_ or settings(),
        "baseline": baseline,
        "fleet": fleet or {"vm1": {}},
    }
    result = checks.mde_linux_checks_suite(data)
    jsonschema.validate(result, SUITE_SCHEMA)
    return result


def by_id(result):
    return {c["id"]: c for c in result["checks"]}


def changed(**health):
    probe = copy.deepcopy(REAL)
    probe["mdatp"]["health"].update(health)
    return probe


# --- The real probe ------------------------------------------------------------------------------


def test_the_real_unlicensed_host_passes_with_reasons_for_every_skip():
    result = by_id(suite())
    failed = {k: c["detail"] for k, c in result.items() if c["status"] in ("failed", "error")}
    assert failed == {}
    skipped = {k for k, c in result.items() if c["status"] == "skipped"}
    assert skipped == {
        "agent_version",
        "offline_cloud_protection",
        "quick_scan",
        "product_expiry",
        "onboarded",
        "organisation",
        "healthy",
        "unique_identity",
        "service_survives_reboot",
        "upgrade_compared",
    }
    assert all(result[k]["detail"] for k in skipped)


def test_check_ids_are_unique_and_stable():
    ids = [c["id"] for c in suite()["checks"]]
    assert len(ids) == len(set(ids))
    # The ids other tools rely on: libre_devops.test_results_report's README names these.
    assert {"real_time_protection", "eicar_detection", "service_survives_reboot"} <= set(ids)


def test_suite_properties_describe_what_was_tested():
    properties = suite()["properties"]
    assert properties["app_version"] == "101.26101.0000"
    assert properties["package"] == "101.26101.0000-1.x86_64"
    assert properties["enforcement_level"] == "real_time"
    assert properties["onboarded"] is False and properties["selinux"] == "enforcing"


# --- The probe's parsers --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "value", "managed"),
    [
        ("true [managed]", True, True),
        ("false", False, False),
        ("unavailable", None, False),
        ('"real_time" [managed]', "real_time", True),
        ('["missing license","engine not available"]', ["missing license", "engine not available"], False),
        ('"["Engine client exited"]"', '["Engine client exited"]', False),
        ("7", 7, False),
        ("Nov 15, 2026 at 09:08:22 PM UTC", "Nov 15, 2026 at 09:08:22 PM UTC", False),
        ('""', "", False),
        ("[]", [], False),
    ],
)
def test_health_values_as_mdatp_prints_them(raw, value, managed):
    assert probe_module.parse_health_value(raw) == (value, managed)


def test_the_real_health_output_parses():
    text = (ROOT / "molecule" / "fixtures" / "rhel9-unlicensed" / "health.txt").read_text()
    fields, managed = probe_module.parse_health(text)
    assert "ATTENTION" not in "".join(fields)
    assert fields["real_time_protection_enabled"] is True and fields["health_issues"] == ["missing license"]
    assert set(managed) == {"passive_mode_enabled", "real_time_protection_enabled", "antivirus_enforcement_level"}
    assert len(fields) == len(REAL["mdatp"]["health"])


@pytest.mark.parametrize(("delta", "seconds"), [("0:00:20.229000", 20.229), ("1:02:03.5", 3723.5), ("1 day, 0:00:01", 86401.0), ("", None)])
def test_command_durations(delta, seconds):
    assert checks.mde_linux_checks_seconds(delta) == seconds


def test_mdatp_dates():
    assert checks.parse_mdatp_date("Jun 20, 2027 at 12:00:00 AM").isoformat() == "2027-06-20T00:00:00"
    assert checks.parse_mdatp_date("Nov 15, 2026 at 09:08:22 PM UTC").isoformat() == "2026-11-15T21:08:22"
    assert checks.parse_mdatp_date("1794776870000").year == 2026
    assert checks.parse_mdatp_date("next spring") is None


# --- Installation ---------------------------------------------------------------------------------


def test_agent_version_compares_with_the_expected_one():
    result = by_id(suite(settings_=settings(expected_version="101.26101.0000")))
    assert result["agent_version"]["status"] == "passed"
    result = by_id(suite(settings_=settings(expected_version="101.26111.0001")))
    assert result["agent_version"]["status"] == "failed" and result["agent_version"]["actual"] == "101.26101.0000"


def test_two_installed_versions_fail():
    probe = copy.deepcopy(REAL)
    probe["package"]["installed"].append(dict(probe["package"]["installed"][0], version="101.26091.0004"))
    assert "2 of mdatp are installed" in by_id(suite(after=probe))["agent_installed"]["detail"]


def test_a_package_signed_by_someone_else_fails():
    probe = copy.deepcopy(REAL)
    probe["package"]["installed"][0]["key_id"] = "deadbeef"
    check = by_id(suite(after=probe))["package_signature"]
    assert check["status"] == "failed" and check["actual"] == "deadbeef"


def test_debian_packages_skip_the_signature_check():
    probe = copy.deepcopy(REAL)
    probe["package"]["manager"] = "dpkg"
    assert by_id(suite(after=probe))["package_signature"]["status"] == "skipped"


def test_changed_files_fail_but_changed_config_files_do_not():
    probe = copy.deepcopy(REAL)
    probe["package"]["verify_lines"] = [
        "S.5....T.  c /etc/opt/microsoft/mdatp/wdavcfg",
        "..5....T.    /opt/microsoft/mdatp/sbin/wdavdaemon",
    ]
    check = by_id(suite(after=probe))["package_files_intact"]
    assert check["status"] == "failed" and "/opt/microsoft/mdatp/sbin/wdavdaemon" in check["output"]
    assert "wdavcfg" not in check["output"]


def test_missing_dependencies_fail():
    probe = copy.deepcopy(REAL)
    probe["package"]["dependencies_rc"] = 1
    probe["package"]["dependencies_output"] = "Unsatisfied dependencies for mdatp: libacl"
    assert by_id(suite(after=probe))["package_dependencies"]["output"].endswith("libacl")


def test_no_health_is_an_error():
    probe = copy.deepcopy(REAL)
    probe["mdatp"]["health"] = {}
    probe["mdatp"]["health_rc"] = 1
    probe["mdatp"]["health_error"] = "Input/output error"
    assert by_id(suite(after=probe))["health_readable"]["status"] == "error"


# --- Stability ------------------------------------------------------------------------------------


def test_a_restart_during_the_checks_fails():
    probe = copy.deepcopy(REAL)
    probe["service"]["NRestarts"] = 1
    probe["service"]["MainPID"] = 4242
    check = by_id(suite(after=probe))["no_service_restarts"]
    assert check["status"] == "failed" and check["metrics"]["restarts"] == 1 and "4242" in check["detail"]


def test_a_disabled_service_fails_with_the_known_upgrade_bug_named():
    probe = copy.deepcopy(REAL)
    probe["service"]["UnitFileState"] = "disabled"
    assert "101.26042.0000" in by_id(suite(after=probe))["service_enabled"]["remediation"]


def test_a_crash_fails():
    probe = copy.deepcopy(REAL)
    probe["logs"]["crash_files"] = ["wdavdaemon.dmp"]
    assert by_id(suite(after=probe))["no_crashes"]["metrics"]["crashes"] == 1


def test_an_unexpected_reboot_fails():
    probe = copy.deepcopy(REAL)
    probe["system"]["boot_id"] = "another-boot"
    assert by_id(suite(after=probe))["no_unexpected_reboot"]["status"] == "failed"


def test_an_engine_that_never_loads_fails():
    result = by_id(
        suite(after=changed(engine_load_status='["Engine client exited"]'), actions_=actions(settle={"seconds": 300, "loaded": False}))
    )
    assert result["engine_loaded"]["status"] == "failed" and "after waiting 300 s" in result["engine_loaded"]["detail"]


def test_journal_errors_are_low_severity():
    probe = copy.deepcopy(REAL)
    probe["logs"]["journal_errors"] = {"available": True, "count": 2, "lines": ["a", "b"]}
    check = by_id(suite(after=probe))["journal_errors"]
    assert check["status"] == "failed" and check["severity"] == "low"


# --- Protection -----------------------------------------------------------------------------------


def test_enforcement_level_against_the_expected_one():
    check = by_id(suite(settings_=settings(expected_enforcement_level="passive")))["enforcement_level"]
    assert check["status"] == "failed" and check["actual"] == "real_time" and check["detail"] == "real_time [managed]."


def test_enforcement_level_is_worked_out_on_versions_without_the_field():
    probe = copy.deepcopy(REAL)
    del probe["mdatp"]["health"]["antivirus_enforcement_level"]
    assert by_id(suite(after=probe))["enforcement_level"]["actual"] == "real_time"
    probe["mdatp"]["health"]["passive_mode_enabled"] = True
    del probe["mdatp"]["details"]["antivirus"]["fields"]["enforcement_level"]
    assert by_id(suite(after=probe))["enforcement_level"]["actual"] == "passive"


def test_real_time_protection_unavailable_fails():
    check = by_id(suite(after=changed(real_time_protection_available=False)))["real_time_protection"]
    assert check["status"] == "failed" and "available: false" in check["detail"]


def test_real_time_protection_is_skipped_when_off_by_design():
    result = by_id(
        suite(
            after=changed(antivirus_enforcement_level="passive", real_time_protection_enabled=False),
            settings_=settings(expected_enforcement_level="passive"),
        )
    )
    assert result["real_time_protection"]["status"] == "skipped"
    assert result["enforcement_level"]["status"] == "passed"


@pytest.mark.parametrize(
    ("subsystem", "status", "severity"),
    [("ebpf", "passed", "high"), ("netlink", "failed", "medium"), ("auditd", "failed", "high"), (None, "error", "high")],
)
def test_supplementary_events(subsystem, status, severity):
    check = by_id(suite(after=changed(supplementary_events_subsystem=subsystem)))["supplementary_events"]
    assert (check["status"], check["severity"]) == (status, severity)


def test_conflicting_applications_fail():
    check = by_id(suite(after=changed(conflicting_applications=["/usr/bin/othersec"])))["conflicting_applications"]
    assert check["status"] == "failed" and "othersec" in check["detail"]


def test_cloud_protection_on_an_offline_host_fails():
    offline = settings(online=False)
    eicar = {"ran": True, "mode": "real_time", "detected": True, "removed": True, "seconds": 40.5, "threat": {"name": "x"}}
    check = by_id(suite(settings_=offline, actions_=actions(eicar=eicar)))["offline_cloud_protection"]
    assert check["status"] == "failed" and "40.5 s" in check["detail"] and check["actual"] == "true"
    assert by_id(suite(after=changed(cloud_enabled=False), settings_=offline))["offline_cloud_protection"]["status"] == "passed"
    assert by_id(suite())["offline_cloud_protection"]["status"] == "skipped"


def test_folder_permission_issues_fail():
    probe = copy.deepcopy(REAL)
    probe["mdatp"]["details"]["permissions"]["fields"]["logs_folder"] = "Missing write permission"
    assert by_id(suite(after=probe))["folder_permissions"]["detail"] == "logs_folder: Missing write permission."


def test_versions_without_newer_fields_skip_rather_than_fail():
    probe = copy.deepcopy(REAL)
    probe["mdatp"]["details"]["features"]["fields"].pop("engine_signature_verification")
    probe["mdatp"]["details"]["permissions"]["fields"] = {}
    result = by_id(suite(after=probe))
    assert result["engine_signature_verification"]["status"] == "skipped"
    assert result["folder_permissions"]["status"] == "skipped"


def test_eicar_not_removed_fails():
    check = by_id(suite(actions_=actions(eicar={"ran": True, "mode": "real_time", "detected": False, "removed": False, "seconds": 60})))
    assert check["eicar_detection"]["status"] == "failed"


def test_eicar_in_audit_mode_needs_a_detection_only():
    eicar = {
        "ran": True,
        "mode": "audit",
        "detected": True,
        "removed": False,
        "seconds": 1.2,
        "threat": {"name": "Virus:DOS/EICAR_Test_File"},
    }
    assert by_id(suite(actions_=actions(eicar=eicar)))["eicar_detection"]["status"] == "passed"


def test_eicar_by_custom_scan_is_skipped_on_an_unlicensed_device():
    eicar = {
        "ran": True,
        "mode": "on_demand",
        "detected": False,
        "removed": False,
        "seconds": 15,
        "scan_rc": 2,
        "scan_output": "No scan is running",
    }
    assert by_id(suite(actions_=actions(eicar=eicar)))["eicar_detection"]["status"] == "skipped"


def test_quick_scan_on_an_onboarded_device():
    probe = changed(licensed=True, healthy=True, health_issues=[], org_id="org")
    probe["mdatp"]["details"]["antivirus"]["fields"]["last_on_demand_scan_files_scanned"] = 41230
    result = by_id(suite(after=probe, actions_=actions(quick_scan={"ran": True, "rc": 0, "seconds": 412.5, "stdout": "Scan succeeded"})))
    assert result["quick_scan"]["status"] == "passed"
    assert result["quick_scan"]["metrics"] == {"duration_seconds": 412.5, "files_scanned": 41230}
    timed_out = by_id(suite(after=probe, actions_=actions(quick_scan={"ran": True, "timed_out": True, "timeout": 1800, "seconds": 1800})))
    assert timed_out["quick_scan"]["status"] == "failed"


def test_definitions_update_that_fails_says_why():
    probe = copy.deepcopy(REAL)
    probe["mdatp"]["health"]["definitions_status"] = "unavailable"
    probe["mdatp"]["details"]["definitions"]["fields"]["definitions_update_fail_reason"] = "connection refused"
    result = by_id(suite(after=probe, actions_=actions(definitions_update={"ran": True, "rc": 1, "stdout": "failed"})))
    assert "connection refused" in result["definitions_update"]["detail"]
    assert result["definitions_current"]["status"] == "failed"


def test_old_definitions_fail_online_and_are_skipped_offline():
    stale = changed(definitions_updated_minutes_ago=60 * 72)
    assert by_id(suite(after=stale))["definitions_current"]["status"] == "failed"
    offline = settings(online=False)
    result = by_id(suite(after=stale, settings_=offline, actions_=actions(definitions_update={"ran": False, "reason": "offline"})))
    assert result["definitions_current"]["status"] == "skipped" and "1.463.319.0" in result["definitions_current"]["detail"]


def test_product_expiry_on_an_onboarded_device():
    soon = changed(licensed=True, product_expiration="Dec 01, 2026 at 12:00:00 AM")
    check = by_id(suite(after=soon))["product_expiry"]
    assert check["status"] == "failed" and check["metrics"]["days_to_expiry"] < 30
    later = changed(licensed=True, product_expiration="Jul 20, 2027 at 12:00:00 AM")
    assert by_id(suite(after=later))["product_expiry"]["status"] == "passed"


# --- Configuration --------------------------------------------------------------------------------


def test_invalid_managed_configuration_is_critical():
    probe = copy.deepcopy(REAL)
    probe["managed"] = {
        "present": True,
        "valid": False,
        "error": "Expecting ',' delimiter",
        "path": "/etc/opt/microsoft/mdatp/managed/mdatp_managed.json",
    }
    check = by_id(suite(after=probe))["managed_config_valid"]
    assert check["status"] == "failed" and check["severity"] == "critical"


def test_managed_settings_the_agent_ignores_fail():
    probe = copy.deepcopy(REAL)
    probe["mdatp"]["managed_fields"] = ["passive_mode_enabled"]
    check = by_id(suite(after=probe))["managed_config_applied"]
    assert check["status"] == "failed" and "real_time_protection_enabled" in check["detail"]


def test_expected_health_fields_become_checks():
    expected = {"cloud_enabled": True, "network_protection_enforcement_level": ["audit", "block"], "made_up_field": 1}
    result = by_id(suite(settings_=settings(expected_health=expected)))
    assert result["health.cloud_enabled"]["status"] == "passed"
    assert result["health.network_protection_enforcement_level"]["status"] == "failed"
    assert result["health.made_up_field"]["detail"] == "mdatp does not report made_up_field."


# --- Onboarding -----------------------------------------------------------------------------------


def test_an_onboarding_package_without_a_licence_fails():
    probe = copy.deepcopy(REAL)
    probe["managed"]["onboarding_file_present"] = True
    result = by_id(suite(after=probe))
    assert result["onboarded"]["status"] == "failed"
    # "missing license" is no longer expected once the device should be onboarded.
    assert result["health_issues"]["status"] == "failed"


def test_an_onboarded_healthy_device_in_the_right_organisation():
    probe = changed(licensed=True, healthy=True, health_issues=[], org_id="00000000-1111-4222-8333-444444444444")
    result = by_id(suite(after=probe, settings_=settings(expected_org_id="00000000-1111-4222-8333-444444444444")))
    assert [result[k]["status"] for k in ("onboarded", "organisation", "healthy", "health_issues")] == ["passed"] * 4
    wrong = by_id(suite(after=probe, settings_=settings(expected_org_id="99999999-1111-4222-8333-444444444444")))
    assert wrong["organisation"]["status"] == "failed"


def test_cloned_hosts_sharing_an_identity_fail():
    guid = REAL["mdatp"]["health"]["machine_guid"]
    fleet = {"vm1": {"machine_guid": guid}, "vm2": {"machine_guid": guid}, "vm3": {"machine_guid": "other"}}
    check = by_id(suite(fleet=fleet))["unique_identity"]
    assert check["status"] == "failed" and "vm2" in check["detail"] and "vm3" not in check["detail"]


def test_failed_connectivity_lists_the_urls():
    output = "Testing connection with https://a.example ... [OK]\nTesting connection with https://b.example ... [ERROR]"
    check = by_id(suite(actions_=actions(connectivity={"ran": True, "rc": 1, "stdout": output, "seconds": 30})))["cloud_connectivity"]
    assert check["status"] == "failed" and check["metrics"]["urls_failed"] == 1 and "b.example" in check["output"]


# --- The system -----------------------------------------------------------------------------------


def test_too_little_room_for_the_next_update_fails():
    probe = copy.deepcopy(REAL)
    probe["system"]["free_mib"]["/opt"] = 300.0
    check = by_id(suite(after=probe))["disk_space_for_updates"]
    assert check["status"] == "failed" and "needs about 519" in check["detail"]


def test_unsupported_file_systems_fail():
    probe = copy.deepcopy(REAL)
    probe["system"]["filesystems"]["/home"] = "nfs4"
    assert "/home (nfs4)" in by_id(suite(after=probe))["filesystems_supported"]["detail"]


def test_selinux_denials_and_policy():
    probe = copy.deepcopy(REAL)
    probe["logs"]["avc_denials"] = {
        "available": True,
        "count": 1,
        "lines": ['type=AVC msg=audit(1.0:1): avc:  denied { read } comm="wdavdaemon"'],
    }
    probe["system"]["selinux"]["modules"] = []
    result = by_id(suite(after=probe))
    assert result["selinux_denials"]["status"] == "failed" and result["selinux_policy"]["status"] == "failed"


def test_selinux_checks_skip_without_selinux():
    probe = copy.deepcopy(REAL)
    probe["system"]["selinux"] = {"present": False, "mode": "disabled"}
    before = copy.deepcopy(probe)
    result = by_id(suite(after=probe, before=before))
    assert result["selinux_policy"]["status"] == result["selinux_denials"]["status"] == "skipped"


def test_a_changed_selinux_mode_fails():
    before = copy.deepcopy(REAL)
    before["system"]["selinux"]["mode"] = "enforcing"
    after = copy.deepcopy(REAL)
    after["system"]["selinux"]["mode"] = "permissive"
    assert by_id(suite(after=after, before=before))["selinux_mode_unchanged"]["status"] == "failed"


def test_resource_metrics():
    check = by_id(suite())["resource_usage"]
    assert check["metrics"] == {"memory_mib": 381.7, "processes": 3, "cpu_percent": 0.3}


# --- Reboot ---------------------------------------------------------------------------------------


def rebooted(**health):
    probe = copy.deepcopy(REAL)
    probe["system"]["boot_id"] = "new-boot"
    probe["taken_at"] = REAL["taken_at"] + 150
    probe["mdatp"]["health"].update(health)
    return probe


def test_the_service_comes_back_after_a_reboot():
    result = by_id(suite(rebooted=rebooted(), actions_=actions(reboot={"ran": True, "seconds": 1})))
    check = result["service_survives_reboot"]
    assert check["status"] == "passed" and check["metrics"]["seconds_until_reachable"] == pytest.approx(150, abs=40)


def test_a_service_left_disabled_after_the_reboot_fails():
    back = rebooted()
    back["service"]["UnitFileState"] = "disabled"
    back["service"]["ActiveState"] = "inactive"
    check = by_id(suite(rebooted=back, actions_=actions(reboot={"ran": True})))["service_survives_reboot"]
    assert check["status"] == "failed" and "mdatp is inactive" in check["detail"]


def test_new_health_issues_after_the_reboot_fail():
    back = rebooted(health_issues=["missing license", "no active event provider"])
    check = by_id(suite(rebooted=back, actions_=actions(reboot={"ran": True})))["service_survives_reboot"]
    assert "no active event provider" in check["detail"]


def test_a_reboot_that_never_came_back_is_an_error():
    check = by_id(suite(actions_=actions(reboot={"ran": True, "failed": True, "msg": "Timed out"})))["service_survives_reboot"]
    assert check["status"] == "error"


# --- Upgrade --------------------------------------------------------------------------------------


def baseline(**health):
    old = copy.deepcopy(REAL)
    old["mdatp"]["version"] = "101.26091.0004"
    old["mdatp"]["health"].update(health)
    snapshot = checks.mde_linux_checks_baseline(old, "vm1")
    snapshot["metrics"]["memory_mib"] = 439.5
    return snapshot


def test_a_clean_upgrade_passes_every_upgrade_check():
    result = by_id(suite(baseline=baseline()))
    upgrade = {k: c["status"] for k, c in result.items() if k.startswith("upgrade")}
    assert upgrade == {k: "passed" for k in upgrade} and len(upgrade) == 9
    assert result["upgrade_resources"]["metrics"]["memory_change_percent"] == -13.2


def test_an_upgrade_that_changed_nothing_fails():
    snapshot = baseline()
    snapshot["version"] = "101.26101.0000"
    assert "nothing was upgraded" in by_id(suite(baseline=snapshot))["upgrade_version"]["detail"]


def test_an_upgrade_that_changed_the_identity_fails():
    check = by_id(suite(baseline=baseline(edr_machine_id="aaaabbbb")))["upgrade_identity"]
    assert check["status"] == "failed" and "edr_machine_id aaaabbbb to" in check["detail"]


def test_an_upgrade_that_changed_a_setting_or_dropped_managed_fails():
    snapshot = baseline(release_ring="InsiderFast")
    snapshot["managed_fields"].append("release_ring")
    check = by_id(suite(baseline=snapshot))["upgrade_settings"]
    assert "release_ring InsiderFast to Production" in check["detail"] and "no longer [managed]" in check["detail"]


def test_an_upgrade_that_removed_health_fields_fails():
    check = by_id(suite(baseline=baseline(retired_field="x")))["upgrade_health_fields"]
    assert check["status"] == "failed" and "retired_field" in check["detail"]


def test_new_dependencies_are_reported_at_info_severity():
    snapshot = baseline()
    snapshot["package"]["requires"] = [r for r in snapshot["package"]["requires"] if r != "libacl"]
    check = by_id(suite(baseline=snapshot))["upgrade_dependencies"]
    assert check["status"] == "failed" and check["severity"] == "info" and "libacl" in check["detail"]


def test_a_missing_snapshot_is_an_error():
    check = by_id(suite(baseline={"schema": "missing", "path": "/nowhere.json"}))["upgrade_compared"]
    assert check["status"] == "error" and "/nowhere.json" in check["detail"]


# --- Settings -------------------------------------------------------------------------------------


def test_skipped_checks_say_so():
    result = by_id(suite(settings_=settings(skip=["selinux_policy", "journal_errors"])))
    assert result["selinux_policy"]["status"] == "skipped" and "mde_linux_checks_skip" in result["selinux_policy"]["detail"]


def test_the_failed_helper_ignores_info_checks():
    assert checks.mde_linux_checks_failed({"checks": [{"status": "failed", "severity": "info"}]}) is False
    assert checks.mde_linux_checks_failed({"checks": [{"status": "error", "severity": "low"}]}) is True
