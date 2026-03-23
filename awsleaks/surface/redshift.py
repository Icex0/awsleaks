from awsleaks.surface.base import BaseCheck


class RedshiftCheck(BaseCheck):
    name = "redshift"

    def run(self):
        redshift = self.session.client("redshift")
        ec2 = self.session.client("ec2")
        paginator = redshift.get_paginator("describe_clusters")

        for page in paginator.paginate():
            for cluster in page.get("Clusters", []):
                if not cluster.get("PubliclyAccessible", False):
                    continue

                identifier = cluster.get("ClusterIdentifier", "")
                endpoint = cluster.get("Endpoint", {})
                address = endpoint.get("Address", "N/A")
                port = endpoint.get("Port", 0)

                sg_ids = [sg["VpcSecurityGroupId"]
                          for sg in cluster.get("VpcSecurityGroups", [])]
                exposed = self._sg_allows_port(ec2, sg_ids, port)

                if exposed:
                    detail = f"EXPOSED | Endpoint: {address}:{port} | SGs: {', '.join(sg_ids)}"
                else:
                    detail = f"PubliclyAccessible but SG blocks port {port} | Endpoint: {address}:{port} | SGs: {', '.join(sg_ids)}"

                self.add_finding(
                    resource=identifier,
                    detail=detail,
                    severity="HIGH" if exposed else "MEDIUM",
                    target=address,
                    ports=[str(port)] if exposed else None,
                )

    def _sg_allows_port(self, ec2, sg_ids, port):
        if not sg_ids:
            return False

        response = ec2.describe_security_groups(GroupIds=sg_ids)
        for sg in response.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)

                if protocol == "-1" or (from_port <= port <= to_port):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            return True
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            return True
        return False
