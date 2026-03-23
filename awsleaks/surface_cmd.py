import os

import boto3

from awsleaks.auth import get_aws_session
from awsleaks import output as out
from awsleaks.surface import ALL_CHECKS, GLOBAL_CHECKS
from awsleaks.surface.route53 import Route53Check


def register(subparsers, add_auth_args):
    parser = subparsers.add_parser("surface", help="Discover internet-exposed AWS resources")
    add_auth_args(parser)
    parser.add_argument(
        "--checks",
        nargs="*",
        default=None,
        help=f"Checks to run, space or comma separated (default: all). Available: {', '.join(ALL_CHECKS.keys())}",
    )
    parser.add_argument(
        "--all-regions",
        action="store_true",
        help="Scan all AWS regions (default: current region only)",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=None,
        help="Specific regions to scan, space or comma separated (e.g. --regions eu-west-1,eu-west-2)",
    )
    parser.add_argument(
        "--subjack",
        action="store_true",
        help="Run subdomain takeover scanning with subjack on Route53 domains",
    )
    parser.set_defaults(func=run)


def _get_all_regions(session):
    """Get all enabled regions for the account."""
    ec2 = session.client("ec2")
    regions = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    ).get("Regions", [])
    return sorted(r["RegionName"] for r in regions)


def _create_regional_session(base_session, region):
    """Create a new session for a specific region, preserving credentials."""
    creds = base_session.get_credentials()
    if creds:
        frozen = creds.get_frozen_credentials()
        return boto3.Session(
            aws_access_key_id=frozen.access_key,
            aws_secret_access_key=frozen.secret_key,
            aws_session_token=frozen.token,
            region_name=region,
        )
    return boto3.Session(
        profile_name=base_session.profile_name,
        region_name=region,
    )


def _parse_regions(args, session):
    """Parse region arguments into a list of regions."""
    if args.all_regions:
        regions = _get_all_regions(session)
        out.status(f"Scanning {len(regions)} regions")
        return regions, True
    elif args.regions:
        regions = []
        for item in args.regions:
            regions.extend(item.split(","))
        valid = _get_all_regions(session)
        invalid = [r for r in regions if r not in valid]
        if invalid:
            out.error(f"Invalid region(s): {', '.join(invalid)}")
            return None, False
        out.status(f"Scanning {len(regions)} region(s): {', '.join(regions)}")
        return regions, True
    else:
        return [session.region_name or "us-east-1"], False


def run(args):
    session = get_aws_session(args)

    # Support both space and comma separated: --checks ec2,rds or --checks ec2 rds
    if args.checks is not None and len(args.checks) == 0:
        print(f"Available checks: {', '.join(ALL_CHECKS.keys())}")
        return
    raw = args.checks or list(ALL_CHECKS.keys())
    checks = []
    for item in raw:
        checks.extend(item.split(","))
    invalid = [c for c in checks if c not in ALL_CHECKS]
    if invalid:
        out.error(f"Unknown checks: {', '.join(invalid)}")
        print(f"    Available: {', '.join(ALL_CHECKS.keys())}")
        return

    regions, multi_region = _parse_regions(args, session)
    if regions is None:
        return

    # Show region info
    if not args.all_regions:
        region_str = ", ".join(regions)
        out.status(f"Scanning region: {region_str}")
        out.warn("Not scanning all regions. Resources in other regions will be missed. Use --all-regions to scan everything.")

    total_findings = 0
    all_findings = []
    route53_check = None

    out.banner("Attack Surface Scan")

    # Run global checks first (not tied to any region)
    global_checks = [c for c in checks if c in GLOBAL_CHECKS]
    regional_checks = [c for c in checks if c not in GLOBAL_CHECKS]

    for check_name in global_checks:
        check_cls = ALL_CHECKS[check_name]
        check = check_cls(session)

        out.header(f"{check_name} (global)")

        try:
            check.run()
        except Exception as e:
            out.error(f"Error: {e}")
            continue

        check.print_findings()
        all_findings.extend(check.findings)
        total_findings += len(check.findings)

        if isinstance(check, Route53Check):
            route53_check = check

    # Run regional checks per region
    for region in regions:
        regional_session = _create_regional_session(session, region) if multi_region else session

        if not regional_checks:
            continue

        if multi_region:
            out.region_header(region)

        for check_name in regional_checks:
            check_cls = ALL_CHECKS[check_name]
            check = check_cls(regional_session)

            out.header(check_name)

            try:
                check.run()
            except Exception as e:
                out.error(f"Error: {e}")
                continue

            check.print_findings()
            all_findings.extend(check.findings)
            total_findings += len(check.findings)

    out.banner(f"Total findings: {total_findings}")

    # Write Route53 domains and run subjack if available
    if route53_check:
        route53_check.write_domains(args.run_dir, run_subjack=args.subjack)

    # Generate nmap targets and hosts file from all findings
    _generate_scan_files(all_findings, args.run_dir)


def _generate_scan_files(findings, run_dir):
    output_dir = run_dir

    # Collect unique targets with their ports
    # target -> { ports: set, resources: list }
    targets = {}
    for f in findings:
        target = f.get("target")
        if not target:
            continue
        if target not in targets:
            targets[target] = {"ports": set(), "check": f["check"], "resources": []}
        for p in f.get("ports", []):
            if p != "ALL":
                targets[target]["ports"].add(p)
        targets[target]["resources"].append(f["resource"])

    if not targets:
        return

    os.makedirs(output_dir, exist_ok=True)

    # hosts.txt — one target per line
    hosts_path = os.path.join(output_dir, "hosts.txt")
    with open(hosts_path, "w") as f:
        for target in sorted(targets.keys()):
            f.write(f"{target}\n")

    # nmap_targets.txt — target:ports format for easy nmap use
    nmap_path = os.path.join(output_dir, "nmap_targets.txt")
    with open(nmap_path, "w") as f:
        for target in sorted(targets.keys()):
            ports = sorted(targets[target]["ports"], key=lambda x: int(x.split("-")[0]))
            resources = ", ".join(targets[target]["resources"])
            if ports:
                check = targets[target]["check"].upper()
                safe_target = target.replace("/", "_").replace(":", "_")
                f.write(f"# {check} - {resources}\n")
                f.write(f"nmap -Pn -sV --open -oA {safe_target} {target} -p {','.join(ports)}\n\n")

    # nmap_scan.sh — ready-to-run script
    script_path = os.path.join(output_dir, "nmap_scan.sh")
    # Filter to only targets with ports
    scannable = [(t, targets[t]) for t in sorted(targets.keys()) if targets[t]["ports"]]
    total = len(scannable)
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("# Generated by awsleaks surface\n")
        f.write(f"# {total} target(s)\n\n")
        f.write("mkdir -p nmap_output\n\n")
        for i, (target, info) in enumerate(scannable, 1):
            ports = sorted(info["ports"], key=lambda x: int(x.split("-")[0]))
            check = info["check"].upper()
            resources = ", ".join(info["resources"])
            safe_target = target.replace("/", "_").replace(":", "_")
            cmd = f"nmap -Pn -sV --open -oA nmap_output/{safe_target} {target} -p {','.join(ports)}"
            f.write(f"echo \"[{i}/{total}] Scanning - {check} - {target} ({resources})\"\n")
            f.write(f"echo \"    $ {cmd}\"\n")
            f.write(f"{cmd}\n\n")
    os.chmod(script_path, 0o755)

    out.status(f"Scan files written to {output_dir}/")
    print(f"    hosts.txt       — {len(targets)} target(s)")
    print(f"    nmap_targets.txt — nmap commands per target")
    print(f"    nmap_scan.sh    — run: ./{script_path}")
