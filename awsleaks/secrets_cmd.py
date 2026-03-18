import os

import boto3

from awsleaks.auth import get_aws_session
from awsleaks import output as out
from awsleaks.scanner import build_betterleaks, scan
from awsleaks.collectors import ALL_COLLECTORS, GLOBAL_COLLECTORS


def register(subparsers, add_auth_args):
    parser = subparsers.add_parser("secrets", help="Scan AWS services for hardcoded secrets")
    add_auth_args(parser)
    parser.add_argument(
        "--services",
        nargs="+",
        default=None,
        help=f"Services to scan, space or comma separated (default: all). Available: {', '.join(ALL_COLLECTORS.keys())}",
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
        "--max-file-size",
        type=int,
        default=200,
        help="Max file size in MB to download from S3 (default: 200MB per file)",
    )
    parser.set_defaults(func=run)


def _get_all_regions(session):
    ec2 = session.client("ec2")
    regions = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    ).get("Regions", [])
    return sorted(r["RegionName"] for r in regions)


def _create_regional_session(base_session, region):
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


def _create_collector(collector_cls, session, args):
    from awsleaks.collectors.s3 import S3Collector
    if collector_cls is S3Collector:
        return collector_cls(session, run_dir=args.run_dir, max_file_size_mb=args.max_file_size)
    return collector_cls(session, run_dir=args.run_dir)


def run(args):
    session = get_aws_session(args)

    build_betterleaks()

    # Support both space and comma separated: --services lambda,glue or --services lambda glue
    raw = args.services or list(ALL_COLLECTORS.keys())
    services = []
    for item in raw:
        services.extend(item.split(","))
    invalid = [s for s in services if s not in ALL_COLLECTORS]
    if invalid:
        out.error(f"Unknown services: {', '.join(invalid)}")
        print(f"    Available: {', '.join(ALL_COLLECTORS.keys())}")
        return

    regions, multi_region = _parse_regions(args, session)
    if regions is None:
        return

    # Phase 1: Collect everything
    collected_by_service = {}
    total = 0

    global_services = [s for s in services if s in GLOBAL_COLLECTORS]
    regional_services = [s for s in services if s not in GLOBAL_COLLECTORS]

    out.banner("Phase 1: Collecting resources")

    # Global services first
    for service in global_services:
        collector_cls = ALL_COLLECTORS[service]
        collector = _create_collector(collector_cls, session, args)
        out.header(f"{service} (global)")

        items = []
        for name, path in collector.collect():
            items.append((name, path))

        collected_by_service[service] = items

        if not items:
            out.none("No resources found")
        else:
            out.info(f"Collected {len(items)} resource(s) from {service}")
            total += len(items)

    # Regional services per region
    for region in regions:
        regional_session = _create_regional_session(session, region) if multi_region else session

        if not regional_services:
            continue

        if multi_region:
            out.region_header(region)

        for service in regional_services:
            collector_cls = ALL_COLLECTORS[service]
            collector = _create_collector(collector_cls, regional_session, args)
            out.header(service)

            items = []
            for name, path in collector.collect():
                items.append((name, path))

            key = f"{service}:{region}" if multi_region else service
            collected_by_service[key] = items

            if not items:
                out.none("No resources found")
            else:
                out.info(f"Collected {len(items)} resource(s) from {service}")
                total += len(items)

    out.banner(f"Total collected: {total} resource(s) across {len(services)} service(s)")

    if total == 0:
        out.none("Nothing to scan")
        return

    # Phase 2: Scan everything
    out.banner("Phase 2: Scanning for secrets")

    report_dir = os.path.join(args.run_dir, "betterleaks_reports")

    for key, items in collected_by_service.items():
        if not items:
            continue

        out.header(f"{key} ({len(items)} resource(s))")

        for name, path in items:
            try:
                scan(path, name, report_dir=report_dir)
            except Exception as e:
                out.error(f"Scan failed for {name}: {e}")
