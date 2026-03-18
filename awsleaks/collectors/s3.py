import json
import os
import subprocess

from botocore.exceptions import ClientError

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out

DEFAULT_MAX_FILE_SIZE_MB = 200


class S3Collector(BaseCollector):
    service_name = "s3"

    def __init__(self, session, max_file_size_mb=DEFAULT_MAX_FILE_SIZE_MB):
        super().__init__(session)
        self.max_file_size = max_file_size_mb * 1024 * 1024

    def collect(self):
        client = self.session.client("s3")

        buckets = client.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                if not self._is_public(client, name):
                    continue

                # Count objects first
                total_objects = 0
                total_size = 0
                paginator = client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=name):
                    for obj in page.get("Contents", []):
                        if not obj["Key"].endswith("/"):
                            total_objects += 1
                            total_size += obj.get("Size", 0)

                if total_size > 1024 * 1024 * 1024:
                    size_str = f"{total_size / 1024 / 1024 / 1024:.1f}GB"
                elif total_size > 1024 * 1024:
                    size_str = f"{total_size / 1024 / 1024:.1f}MB"
                else:
                    size_str = f"{total_size / 1024:.0f}KB"
                out.error(f"S3 bucket '{name}' is PUBLIC — {total_objects} file(s), {size_str}")
                answer = input(f"    Download '{name}'? [y/N]: ").strip().lower()
                if answer in ("y", "yes"):
                    yield from self._download_bucket(client, name)
                else:
                    print(f"    Skipped '{name}'")
            except Exception as e:
                out.error(f"S3 {name}: {e}")

    def _is_public(self, client, bucket):
        # Check public access block first
        access_block_allows = False
        try:
            pab = client.get_public_access_block(Bucket=bucket)
            config = pab.get("PublicAccessBlockConfiguration", {})
            # If any of these are False, public access is not fully blocked
            if not config.get("BlockPublicAcls", True) or \
               not config.get("IgnorePublicAcls", True) or \
               not config.get("BlockPublicPolicy", True) or \
               not config.get("RestrictPublicBuckets", True):
                access_block_allows = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                # No block configured = public access not blocked
                access_block_allows = True
            else:
                raise

        if not access_block_allows:
            return False

        # Check bucket policy for Principal: "*"
        try:
            policy_str = client.get_bucket_policy(Bucket=bucket).get("Policy", "")
            policy = json.loads(policy_str)
            for statement in policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                principal = statement.get("Principal", "")
                if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
                    return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                pass
            else:
                raise

        # Check bucket ACL for public grants
        try:
            acl = client.get_bucket_acl(Bucket=bucket)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    return True
        except ClientError:
            pass

        return False

    def _download_bucket(self, client, bucket):
        bucket_dir = os.path.join(self.output_dir, bucket)
        os.makedirs(bucket_dir, exist_ok=True)

        # Build aws s3 sync command with --exclude for files > 200MB
        cmd = ["aws", "s3", "sync", f"s3://{bucket}", bucket_dir]

        # Add profile if session has one
        profile = self.session.profile_name
        if profile:
            cmd.extend(["--profile", profile])

        # Exclude files > 200MB by listing them first
        out.status("Checking for files > 200MB to exclude...")
        paginator = client.get_paginator("list_objects_v2")
        excluded = 0
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                if obj.get("Size", 0) > self.max_file_size:
                    cmd.extend(["--exclude", obj["Key"]])
                    excluded += 1

        if excluded:
            out.status(f"Excluding {excluded} file(s) over 200MB")

        out.status(f"Syncing s3://{bucket} (using aws s3 sync with parallel transfers)...")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            out.error(f"aws s3 sync failed for {bucket}")

        yield (f"s3_{bucket}", bucket_dir)
