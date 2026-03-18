import json
import os
import subprocess

from awsleaks import output as out

BL_SRC_DIR = "betterleaks_src"
BL_BINARY = os.path.join(BL_SRC_DIR, "betterleaks")
REPORT_DIR = "betterleaks_reports"


def build_betterleaks():
    if os.path.exists(BL_BINARY):
        out.none("BetterLeaks binary exists, skipping build")
        return

    out.status("Cloning BetterLeaks repository")
    subprocess.run(["git", "clone", "https://github.com/betterleaks/betterleaks.git", BL_SRC_DIR], check=True)

    out.status("Building BetterLeaks")
    subprocess.run(["make", "build"], cwd=BL_SRC_DIR, check=True)
    out.status("BetterLeaks build complete")


def scan(path, name):
    """Run BetterLeaks on a directory and print any findings."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_DIR, f"{name}_betterleaks.json")
    out.info(f"Scanning {name}")

    cmd = [
        BL_BINARY, "dir", path,
        "--report-path", report_path,
        "--report-format", "json",
        "--no-banner", "-v",
    ]
    subprocess.run(cmd)

    if not os.path.exists(report_path):
        return

    with open(report_path) as f:
        leaks = json.load(f)

    if not leaks:
        os.remove(report_path)
        return

    out.header(f"Secrets Found in {name}")
    for leak in leaks:
        out.warn(f"[{leak.get('RuleID')}] {leak.get('File')}:{leak.get('StartLine')}")
        out.detail(f"SECRET: {leak.get('Secret')}")
