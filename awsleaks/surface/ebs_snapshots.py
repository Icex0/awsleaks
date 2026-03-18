from awsleaks.surface.base import BaseCheck


class EBSSnapshotCheck(BaseCheck):
    name = "ebs-snapshots"

    def run(self):
        client = self.session.client("ec2")
        paginator = client.get_paginator("describe_snapshots")

        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                snap_id = snap["SnapshotId"]
                encrypted = snap.get("Encrypted", False)

                # Check if shared publicly
                try:
                    attrs = client.describe_snapshot_attribute(
                        SnapshotId=snap_id,
                        Attribute="createVolumePermission",
                    ).get("CreateVolumePermissions", [])
                except Exception:
                    continue

                is_public = any(
                    p.get("Group") == "all" for p in attrs
                )

                if not is_public:
                    continue

                size = snap.get("VolumeSize", 0)
                description = snap.get("Description", "")[:80]

                if encrypted:
                    detail = f"Public but encrypted (KMS key required) | Size: {size}GB | {description}"
                else:
                    detail = f"EXPOSED | Public & unencrypted | Size: {size}GB | {description}"

                self.add_finding(resource=snap_id, detail=detail)
