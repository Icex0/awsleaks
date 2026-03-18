from awsleaks.surface.base import BaseCheck


class ECSCheck(BaseCheck):
    name = "ecs"

    def run(self):
        client = self.session.client("ecs")
        ec2 = self.session.client("ec2")
        sg_cache = {}

        clusters = client.list_clusters().get("clusterArns", [])

        for cluster_arn in clusters:
            service_arns = []
            paginator = client.get_paginator("list_services")
            for page in paginator.paginate(cluster=cluster_arn):
                service_arns.extend(page.get("serviceArns", []))

            if not service_arns:
                continue

            for i in range(0, len(service_arns), 10):
                batch = service_arns[i:i + 10]
                services = client.describe_services(
                    cluster=cluster_arn, services=batch
                ).get("services", [])

                for svc in services:
                    svc_name = svc.get("serviceName", "")
                    net_config = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
                    if net_config.get("assignPublicIp") != "ENABLED":
                        continue

                    sg_ids = net_config.get("securityGroups", [])
                    cluster_name = cluster_arn.split("/")[-1]

                    open_ports = sorted(set(self._get_open_ports(ec2, sg_ids, sg_cache)),
                                        key=lambda x: (x != "ALL", int(x.split("-")[0]) if x != "ALL" else 0))

                    if open_ports:
                        detail = f"EXPOSED | Public IP enabled | SGs: {', '.join(sg_ids)} | Ports: {', '.join(open_ports)}"
                    else:
                        detail = f"Public IP but SG blocks all inbound | SGs: {', '.join(sg_ids)}"

                    self.add_finding(
                        resource=f"{cluster_name}/{svc_name}",
                        detail=detail,
                        ports=open_ports if open_ports else None,
                    )

    def _get_open_ports(self, ec2, sg_ids, sg_cache):
        open_ports = []
        for sg_id in sg_ids:
            if sg_id not in sg_cache:
                response = ec2.describe_security_groups(GroupIds=[sg_id])
                sg_cache[sg_id] = response.get("SecurityGroups", [{}])[0]

            sg = sg_cache[sg_id]
            for rule in sg.get("IpPermissions", []):
                is_open = False
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        is_open = True
                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        is_open = True

                if not is_open:
                    continue

                protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)

                if protocol == "-1":
                    open_ports.append("ALL")
                elif from_port == to_port:
                    open_ports.append(str(from_port))
                else:
                    open_ports.append(f"{from_port}-{to_port}")

        return open_ports
