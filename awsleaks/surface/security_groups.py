from awsleaks.surface.base import BaseCheck


class SecurityGroupCheck(BaseCheck):
    name = "security-groups"

    def run(self):
        client = self.session.client("ec2")
        paginator = client.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")

                for rule in sg.get("IpPermissions", []):
                    protocol = rule.get("IpProtocol", "")
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 0)

                    # Check for 0.0.0.0/0 or ::/0
                    open_cidrs = []
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            open_cidrs.append("0.0.0.0/0")
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            open_cidrs.append("::/0")

                    if not open_cidrs:
                        continue

                    if protocol == "-1":
                        port_str = "ALL PORTS"
                        severity = "CRITICAL"
                    elif from_port == to_port:
                        port_str = f"port {from_port}"
                        severity = "CRITICAL" if from_port in (22, 3389, 3306, 5432, 1433, 6379, 27017) else "HIGH"
                    else:
                        port_str = f"ports {from_port}-{to_port}"
                        severity = "HIGH"

                    self.add_finding(
                        resource=f"{sg_id} ({sg_name})",
                        detail=f"Inbound {protocol} {port_str} open to {', '.join(open_cidrs)}",
                        severity=severity,
                    )
