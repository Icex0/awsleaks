from awsleaks.surface.base import BaseCheck


class EKSCheck(BaseCheck):
    name = "eks"

    def run(self):
        client = self.session.client("eks")
        clusters = client.list_clusters().get("clusters", [])

        for cluster_name in clusters:
            try:
                cluster = client.describe_cluster(name=cluster_name).get("cluster", {})
                endpoint = cluster.get("endpoint", "")
                access = cluster.get("resourcesVpcConfig", {})
                public_access = access.get("endpointPublicAccess", False)
                public_cidrs = access.get("publicAccessCidrs", [])

                if not public_access:
                    continue

                if "0.0.0.0/0" in public_cidrs:
                    detail = f"EXPOSED | URL: {endpoint} | CIDRs: {', '.join(public_cidrs)}"
                else:
                    detail = f"Restricted | URL: {endpoint} | CIDRs: {', '.join(public_cidrs)}"

                self.add_finding(resource=cluster_name, detail=detail, severity=severity)
            except Exception as e:
                self.add_finding(
                    resource=cluster_name,
                    detail=f"Error checking: {e}",
                    severity="HIGH",
                )
