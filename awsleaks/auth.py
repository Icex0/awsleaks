import sys

import boto3
import botocore.exceptions

from awsleaks import output as out


def get_aws_session(args):
    """Create a boto3 session from args, env vars, or existing AWS config."""
    if args.access_key and args.secret_key:
        session = boto3.Session(
            aws_access_key_id=args.access_key,
            aws_secret_access_key=args.secret_key,
            aws_session_token=args.session_token,
            region_name=args.region,
        )
    elif args.profile:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    else:
        session = boto3.Session(region_name=args.region)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        out.status(f"Authenticated as {identity['Arn']}")
        return session
    except (botocore.exceptions.NoCredentialsError,
            botocore.exceptions.PartialCredentialsError):
        out.error("No AWS credentials found. Provide them via:")
        print("    - CLI args: --access-key, --secret-key, --session-token")
        print("    - Env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN")
        print("    - AWS profile: --profile <name>")
        print("    - SSO: aws configure sso && aws sso login --profile <name>")
        print("    - Default AWS config: aws configure")
        sys.exit(1)
    except botocore.exceptions.TokenRetrievalError:
        profile_name = args.profile or "default"
        out.error(f"SSO token expired. Run:")
        print(f"    aws sso login --profile {profile_name}")
        sys.exit(1)
    except botocore.exceptions.SSOTokenLoadError:
        profile_name = args.profile or "default"
        out.error(f"SSO token expired or missing. Run:")
        print(f"    aws sso login --profile {profile_name}")
        sys.exit(1)
    except botocore.exceptions.UnauthorizedSSOTokenError:
        profile_name = args.profile or "default"
        out.error(f"SSO token expired. Run:")
        print(f"    aws sso login --profile {profile_name}")
        sys.exit(1)
    except botocore.exceptions.ClientError as e:
        out.error(f"Authentication failed: {e}")
        sys.exit(1)
