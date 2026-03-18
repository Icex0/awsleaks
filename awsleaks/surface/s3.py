import json

from botocore.exceptions import ClientError

from awsleaks.surface.base import BaseCheck


class S3Check(BaseCheck):
    name = "s3"

    def run(self):
        client = self.session.client("s3")

        buckets = client.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                reasons = self._check_public(client, name)
                if reasons:
                    region = self._get_bucket_region(client, name)
                    example = self._get_first_object(client, name)
                    if example:
                        url = f"https://{name}.s3.{region}.amazonaws.com/{example}"
                    else:
                        url = f"https://{name}.s3.{region}.amazonaws.com"
                    self.add_finding(
                        resource=name,
                        detail=f"EXPOSED | Example: {url} | {' | '.join(reasons)}",
                        severity="CRITICAL",
                    )
            except Exception as e:
                self.add_finding(
                    resource=name,
                    detail=f"Error checking: {e}",
                    severity="HIGH",
                )

    def _check_public(self, client, bucket):
        reasons = []

        # Check public access block
        block_off = False
        try:
            pab = client.get_public_access_block(Bucket=bucket)
            config = pab.get("PublicAccessBlockConfiguration", {})
            disabled = [k for k, v in config.items() if not v]
            if disabled:
                block_off = True
                reasons.append(f"Public access blocking not active: {', '.join(disabled)}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                block_off = True
                reasons.append("No public access block configured")
            else:
                raise

        if not block_off:
            return []

        # Check bucket policy for Principal: *
        try:
            policy_str = client.get_bucket_policy(Bucket=bucket).get("Policy", "")
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", "")
                if principal == "*" or (isinstance(principal, dict) and "*" in principal.values()):
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    reasons.append(f"Policy allows Principal:* actions: {', '.join(actions)}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise

        # Check ACL
        try:
            acl = client.get_bucket_acl(Bucket=bucket)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                perm = grant.get("Permission", "")
                if "AllUsers" in uri:
                    reasons.append(f"ACL grants AllUsers: {perm}")
                elif "AuthenticatedUsers" in uri:
                    reasons.append(f"ACL grants AuthenticatedUsers: {perm}")
        except ClientError:
            pass

        # Only return if there's actual public exposure beyond just missing block
        return reasons if len(reasons) > 1 else []

    def _get_bucket_region(self, client, bucket):
        try:
            loc = client.get_bucket_location(Bucket=bucket).get("LocationConstraint")
            # None means us-east-1
            return loc or "us-east-1"
        except Exception:
            return "us-east-1"

    def _get_first_object(self, client, bucket):
        try:
            resp = client.list_objects_v2(Bucket=bucket, MaxKeys=1)
            contents = resp.get("Contents", [])
            if contents:
                return contents[0]["Key"]
        except Exception:
            pass
        return None
