from awsleaks.surface.base import BaseCheck


class RDSCheck(BaseCheck):
    name = "rds"

    def run(self):
        rds = self.session.client("rds")
        ec2 = self.session.client("ec2")
        paginator = rds.get_paginator("describe_db_instances")

        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if not db.get("PubliclyAccessible", False):
                    continue

                identifier = db.get("DBInstanceIdentifier", "")
                engine = db.get("Engine", "")
                endpoint = db.get("Endpoint", {})
                address = endpoint.get("Address", "N/A")
                port = endpoint.get("Port", 0)

                # Check if any attached SG allows inbound on this port from 0.0.0.0/0
                sg_ids = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
                exposed = self._sg_allows_port(ec2, sg_ids, port)

                if exposed:
                    detail = f"EXPOSED | Endpoint: {address} | SGs: {', '.join(sg_ids)} | Ports: {port}"
                else:
                    detail = f"PubliclyAccessible but SG blocks port | Endpoint: {address} | SGs: {', '.join(sg_ids)}"

                self.add_finding(
                    resource=f"{identifier} ({engine})",
                    detail=detail,
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

                # Check if this rule covers our port
                if protocol == "-1" or (from_port <= port <= to_port):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            return True
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            return True
        return False
