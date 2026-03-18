import argparse
import sys
from datetime import datetime

from awsleaks import secrets_cmd, surface_cmd


def add_auth_args(parser):
    parser.add_argument("--access-key", help="AWS Access Key ID (or set AWS_ACCESS_KEY_ID)")
    parser.add_argument("--secret-key", help="AWS Secret Access Key (or set AWS_SECRET_ACCESS_KEY)")
    parser.add_argument("--session-token", help="AWS Session Token (or set AWS_SESSION_TOKEN)")
    parser.add_argument("--region", default=None, help="AWS Region (or set AWS_DEFAULT_REGION)")
    parser.add_argument("--profile", default=None, help="AWS profile name (supports SSO)")


def main():
    parser = argparse.ArgumentParser(
        prog="awsleaks",
        description="AWS security scanner — find secrets and exposed assets",
    )

    subparsers = parser.add_subparsers(dest="command")

    secrets_cmd.register(subparsers, add_auth_args)
    surface_cmd.register(subparsers, add_auth_args)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.run_dir = f"awsleaks_{args.command}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    args.func(args)


if __name__ == "__main__":
    main()
