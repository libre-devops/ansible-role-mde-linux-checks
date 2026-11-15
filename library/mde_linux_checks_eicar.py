#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Craig Thacker (Libre DevOps). MIT licence: see LICENSE.
"""Prove the antivirus detects the EICAR test file, and time how long it takes.

EICAR is the industry's harmless antivirus test string. This module writes it to a file, then
waits for Defender to act in the way its enforcement level promises: real_time removes it,
audit reports it without removing it, and on_demand or passive (no real-time protection) is
tested with a custom scan of the file. It then removes the file and its quarantine entry, so
the host is left as it was, apart from the detection in Defender's history and an EICAR alert
in the tenant when the device is onboarded (that alert is expected).

The test string is put together from two halves, so no file in this repository holds it whole
and no scanner quarantines the repository.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: mde_linux_checks_eicar
short_description: Check Defender for Endpoint detects the EICAR test file
description:
  - Writes the EICAR test file and waits for the detection the enforcement level calls for, then cleans up.
options:
  directory:
    description: Directory for the test file. It must be on a file system real-time protection watches.
    type: path
    required: true
  mode:
    description:
      - real_time expects the file removed; audit expects a detection with the file left; on_demand scans the file and
        expects a detection.
    type: str
    choices: [real_time, audit, on_demand]
    required: true
  timeout:
    description: Seconds to wait for the detection.
    type: float
    default: 60
author:
  - Craig Thacker
"""

import json
import os
import time

from ansible.module_utils.basic import AnsibleModule

FIRST_HALF = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
SECOND_HALF = "ANTIVIRUS-TEST-FILE!$H+H*"


def threats_for(module, path):
    """Detections of the file in Defender's history, newest last."""
    rc, out, _ = module.run_command(["mdatp", "threat", "list", "--output", "json"], environ_update={"LANG": "C"})
    start = out.find("{")
    if rc != 0 or start < 0:
        return []
    try:
        history = json.loads(out[start:])
    except ValueError:
        return []
    found = []
    for scan in (history.get("threats") or {}).get("scans") or []:
        for entry in scan.get("threats") or []:
            threat = entry.get("threat") or {}
            for resource in threat.get("infected_resources") or []:
                if resource.get("path") == path:
                    found.append(
                        {
                            "id": threat.get("tracking_id"),
                            "name": threat.get("name"),
                            "status": threat.get("status"),
                            "scan_type": resource.get("scan_type") or scan.get("type"),
                        }
                    )
    return found


def main():
    module = AnsibleModule(
        argument_spec=dict(
            directory=dict(type="path", required=True),
            mode=dict(type="str", required=True, choices=["real_time", "audit", "on_demand"]),
            timeout=dict(type="float", default=60),
        ),
        supports_check_mode=False,
    )
    directory, mode, timeout = module.params["directory"], module.params["mode"], module.params["timeout"]
    if not os.path.isdir(directory):
        os.makedirs(directory, 0o700)
    path = os.path.join(directory, "eicar-%d-%d.com" % (int(time.time()), os.getpid()))
    result = {
        "changed": True,
        "mode": mode,
        "path": path,
        "detected": False,
        "removed": False,
        "seconds": None,
        "threat": None,
        "scan_rc": None,
        "scan_output": None,
        "cleanup": [],
    }

    started = time.time()
    try:
        with open(path, "w") as handle:
            handle.write(FIRST_HALF + SECOND_HALF)
    except (IOError, OSError) as exc:
        # Real-time protection can stop the write itself, which is a detection too.
        result["write_error"] = str(exc)

    if mode == "on_demand":
        rc, out, err = module.run_command(["mdatp", "scan", "custom", "--path", path], environ_update={"LANG": "C"})
        result["scan_rc"], result["scan_output"] = rc, (out + err).strip()[-2000:]

    deadline = started + timeout
    while True:
        exists = os.path.exists(path)
        threats = threats_for(module, path)
        if threats:
            result["detected"], result["threat"] = True, threats[-1]
        if not exists:
            result["removed"] = True
        done = (mode == "real_time" and result["removed"]) or (mode != "real_time" and result["detected"])
        if done or time.time() >= deadline:
            break
        time.sleep(0.25 if time.time() - started < 5 else 1)
    result["seconds"] = round(time.time() - started, 3)
    if result["removed"] and not result["detected"]:
        # The file went before the history showed it: look once more.
        threats = threats_for(module, path)
        if threats:
            result["detected"], result["threat"] = True, threats[-1]

    # Leave the host as it was: the file, and the quarantined copy of it.
    if os.path.exists(path):
        try:
            os.remove(path)
            result["cleanup"].append("removed the test file")
        except OSError as exc:
            result["cleanup"].append("could not remove the test file: %s" % exc)
    if result["threat"] and result["threat"].get("id"):
        rc, out, err = module.run_command(
            ["mdatp", "threat", "quarantine", "remove", "--id", result["threat"]["id"]], environ_update={"LANG": "C"}
        )
        note = (out + err).replace("ATTENTION: No license found. Contact your administrator for help.", "").strip()
        result["cleanup"].append("removed the quarantined copy" if rc == 0 else "quarantine: %s" % (note[-300:] or "exit %s" % rc))
    module.exit_json(**result)


if __name__ == "__main__":
    main()
