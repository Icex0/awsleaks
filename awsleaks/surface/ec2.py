from awsleaks.surface.base import BaseCheck


class EC2Check(BaseCheck):
    name = "ec2"

    note = "Public IPs with open ports may be intentional (web servers, bastion hosts, etc.)"

    def run(self):
        client = self.session.client("ec2")
        paginator = client.get_paginator("describe_instances")

        # Cache SG rules to avoid repeated API calls
        sg_cache = {}

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    state = instance.get("State", {}).get("Name", "")
                    if state != "running":
                        continue

                    public_ip = instance.get("PublicIpAddress")
                    if not public_ip:
                        continue

                    public_dns = instance.get("PublicDnsName", "")
                    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                    name_tag = ""
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name_tag = tag["Value"]
                            break

                    # Check which ports are open to 0.0.0.0/0
                    open_ports = sorted(set(self._get_open_ports(client, sg_ids, sg_cache)),
                                        key=lambda x: (x != "ALL", int(x.split("-")[0]) if x != "ALL" else 0))

                    if not open_ports:
                        continue

                    resource = f"{instance_id} ({name_tag})" if name_tag else instance_id
                    dns_part = f" | DNS: {public_dns}" if public_dns else ""
                    detail = f"EXPOSED | IP: {public_ip}{dns_part} | SGs: {', '.join(sg_ids)} | Ports: {', '.join(open_ports)}"

                    self.add_finding(
                        resource=resource,
                        detail=detail,
                        target=public_ip,
                        ports=open_ports,
                    )

    def _get_open_ports(self, client, sg_ids, sg_cache):
        open_ports = []

        for sg_id in sg_ids:
            if sg_id not in sg_cache:
                response = client.describe_security_groups(GroupIds=[sg_id])
                sg_cache[sg_id] = response.get("SecurityGroups", [{}])[0]

            sg = sg_cache[sg_id]
            for rule in sg.get("IpPermissions", []):
                # Check for 0.0.0.0/0 or ::/0
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
