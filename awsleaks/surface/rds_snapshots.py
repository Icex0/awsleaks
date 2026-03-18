from awsleaks.surface.base import BaseCheck


class RDSSnapshotCheck(BaseCheck):
    name = "rds-snapshots"

    def run(self):
        client = self.session.client("rds")

        # Check DB snapshots
        paginator = client.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            for snap in page.get("DBSnapshots", []):
                self._check_snapshot(client, snap)

        # Check DB cluster snapshots (Aurora)
        paginator = client.get_paginator("describe_db_cluster_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            for snap in page.get("DBClusterSnapshots", []):
                self._check_cluster_snapshot(client, snap)

    def _check_snapshot(self, client, snap):
        snap_id = snap["DBSnapshotIdentifier"]

        attrs = client.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snap_id
        ).get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", [])

        for attr in attrs:
            if attr.get("AttributeName") == "restore":
                if "all" in attr.get("AttributeValues", []):
                    engine = snap.get("Engine", "")
                    size = snap.get("AllocatedStorage", 0)
                    detail = f"EXPOSED | Public snapshot | Engine: {engine} | Size: {size}GB"
                    self.add_finding(resource=snap_id, detail=detail)

    def _check_cluster_snapshot(self, client, snap):
        snap_id = snap["DBClusterSnapshotIdentifier"]

        attrs = client.describe_db_cluster_snapshot_attributes(
            DBClusterSnapshotIdentifier=snap_id
        ).get("DBClusterSnapshotAttributesResult", {}).get("DBClusterSnapshotAttributes", [])

        for attr in attrs:
            if attr.get("AttributeName") == "restore":
                if "all" in attr.get("AttributeValues", []):
                    engine = snap.get("Engine", "")
                    detail = f"EXPOSED | Public cluster snapshot | Engine: {engine}"
                    self.add_finding(resource=snap_id, detail=detail)
