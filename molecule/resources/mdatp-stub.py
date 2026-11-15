#!/usr/bin/env python3
"""A stand-in for the mdatp command in the Molecule containers.

The real agent cannot license itself or run its antivirus in a container, so this answers mdatp's
commands with output captured from a real RHEL 9 VM (molecule/fixtures/<set>/), which the
prepare step bundles into /etc/mdatp-stub.json. It also plays real-time protection for the EICAR
test: listing threats finds any eicar-*.com file in the checks' work directory, records a detection
and removes the file, as the agent does. Installed as /usr/bin/mdatp, in place of the real command.
"""

import json
import os
import sys
import uuid
import zipfile

FIXTURES = "/etc/mdatp-stub.json"
STATE = "/var/lib/mdatp-stub/threats.json"
WORK_DIR = "/var/tmp/mde-linux-checks"
BANNER = "ATTENTION: No license found. Contact your administrator for help."


def fixture(name, default=None):
    with open(FIXTURES) as handle:
        bundle = json.load(handle)
    if name not in bundle and default is not None:
        return default
    return bundle[name]


def out(text, rc=0):
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    sys.exit(rc)


def threats():
    state = []
    if os.path.exists(STATE):
        with open(STATE) as handle:
            state = json.load(handle)
    if os.path.isdir(WORK_DIR):
        for name in sorted(os.listdir(WORK_DIR)):
            if name.startswith("eicar-") and name.endswith(".com"):
                path = os.path.join(WORK_DIR, name)
                state.append(
                    {
                        "tracking_id": str(uuid.uuid4()),
                        "name": "Virus:DOS/EICAR_Test_File",
                        "type": "virus",
                        "status": "infected",
                        "infected_resources": [{"$type": "infected_file", "scan_type": "real_time", "path": path}],
                    }
                )
                os.remove(path)
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w") as handle:
        json.dump(state, handle)
    return {
        "threats": {"scans": [{"type": "real_time", "state": "succeeded", "files_scanned": 1, "threats": [{"threat": t} for t in state]}]}
    }


def main(args):
    if args == ["version"]:
        out(fixture("version.txt"))
    if args[:1] == ["health"]:
        if args == ["health"]:
            out(fixture("health.txt"))
        if args == ["health", "--output", "json"]:
            out(fixture("health.json"))
        if len(args) == 3 and args[1] == "--details":
            out(fixture(f"details-{args[2]}.txt"))
        if len(args) == 3 and args[1] == "--field":
            for line in fixture("health.txt").splitlines():
                if line.split(" ", 1)[0] == args[2]:
                    value = line.split(":", 1)[1].strip().replace(" [managed]", "")
                    out(BANNER + "\n" + value)
            out(BANNER + "\nInvalid argument", 2)
    if args == ["threat", "list", "--output", "json"]:
        out(json.dumps(threats()))
    if args[:3] == ["threat", "quarantine", "remove"]:
        out("Removed from quarantine")
    if args == ["exclusion", "list", "--output", "json"]:
        out(fixture("exclusions.json"))
    if args == ["definitions", "update"]:
        out(
            fixture("definitions-update.txt"),
            int(fixture("definitions-update.rc", "0").strip()),
        )
    if args == ["connectivity", "test"]:
        out(
            fixture("connectivity.txt"),
            int(fixture("connectivity.rc", "0").strip()),
        )
    if args[:2] == ["scan", "quick"] or args[:2] == ["scan", "custom"]:
        out(fixture("scan-quick.txt"), int(fixture("scan-quick.rc").strip()))
    if args == ["scan", "cancel"]:
        out("Scan cancelled")
    if args[:2] == ["diagnostic", "create"]:
        directory = args[args.index("--path") + 1] if "--path" in args else "/tmp"
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{uuid.uuid4()}.zip")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("health.txt", fixture("health.txt"))
        out(f'{BANNER}\nDiagnostic file created: "{path}"')
    out(BANNER + "\nInvalid argument", 2)


if __name__ == "__main__":
    main(sys.argv[1:])
