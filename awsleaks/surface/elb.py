from awsleaks.surface.base import BaseCheck


class ELBCheck(BaseCheck):
    name = "elb"

    note = "Internet-facing load balancers are expected for public services but could also expose services if security groups are misconfigured."

    def run(self):
        self._ec2 = self.session.client("ec2")
        self._check_alb_nlb()
        self._check_classic()

    def _check_alb_nlb(self):
        client = self.session.client("elbv2")
        paginator = client.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if lb.get("Scheme") != "internet-facing":
                    continue

                name = lb.get("LoadBalancerName", "")
                lb_type = lb.get("Type", "")
                dns = lb.get("DNSName", "")
                sg_ids = lb.get("SecurityGroups", [])

                # Get listener ports
                lb_arn = lb.get("LoadBalancerArn", "")
                listener_ports = []
                try:
                    listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                    listener_ports = [int(l.get("Port", 0)) for l in listeners]
                except Exception:
                    pass

                # Filter listener ports by SG open ports
                if sg_ids:
                    open_ports = self._get_sg_open_ports(sg_ids)
                    reachable = sorted(set(str(p) for p in listener_ports if p in open_ports),
                                       key=lambda x: int(x))
                    blocked = sorted(set(str(p) for p in listener_ports if p not in open_ports),
                                     key=lambda x: int(x))
                else:
                    # NLBs without SGs — all listener ports are reachable
                    reachable = sorted(set(str(p) for p in listener_ports), key=lambda x: int(x))
                    blocked = []

                if reachable:
                    port_str = ", ".join(reachable)
                    detail = f"Internet-facing | DNS: {dns} | SGs: {', '.join(sg_ids)} | Ports: {port_str}"
                    if blocked:
                        detail += f" | SG-blocked: {', '.join(blocked)}"
                    self.add_finding(
                        resource=f"{name} ({lb_type})",
                        detail=detail,
                        severity="MEDIUM",
                        target=dns,
                        ports=reachable,
                    )
                elif listener_ports:
                    detail = f"Internet-facing but SG blocks all listener ports | DNS: {dns} | SGs: {', '.join(sg_ids)}"
                    self.add_finding(
                        resource=f"{name} ({lb_type})",
                        detail=detail,
                        severity="MEDIUM",
                    )

    def _check_classic(self):
        client = self.session.client("elb")
        lbs = client.describe_load_balancers().get("LoadBalancerDescriptions", [])

        for lb in lbs:
            if lb.get("Scheme") != "internet-facing":
                continue

            name = lb.get("LoadBalancerName", "")
            dns = lb.get("DNSName", "")
            sg_ids = lb.get("SecurityGroups", [])
            listener_ports = [l.get("Listener", {}).get("LoadBalancerPort", 0)
                              for l in lb.get("ListenerDescriptions", [])]

            if sg_ids:
                open_ports = self._get_sg_open_ports(sg_ids)
                reachable = sorted(set(str(p) for p in listener_ports if p in open_ports),
                                   key=lambda x: int(x))
                blocked = sorted(set(str(p) for p in listener_ports if p not in open_ports),
                                 key=lambda x: int(x))
            else:
                reachable = sorted(set(str(p) for p in listener_ports), key=lambda x: int(x))
                blocked = []

            if reachable:
                port_str = ", ".join(reachable)
                detail = f"Internet-facing | DNS: {dns} | SGs: {', '.join(sg_ids)} | Ports: {port_str}"
                if blocked:
                    detail += f" | SG-blocked: {', '.join(blocked)}"
                self.add_finding(
                    resource=f"{name} (classic)",
                    detail=detail,
                    severity="MEDIUM",
                    target=dns,
                    ports=reachable,
                )
            elif listener_ports:
                detail = f"Internet-facing but SG blocks all listener ports | DNS: {dns} | SGs: {', '.join(sg_ids)}"
                self.add_finding(
                    resource=f"{name} (classic)",
                    detail=detail,
                    severity="MEDIUM",
                )

    def _get_sg_open_ports(self, sg_ids):
        """Return set of ports open to 0.0.0.0/0 or ::/0 across all given SGs."""
        open_ports = set()
        try:
            response = self._ec2.describe_security_groups(GroupIds=sg_ids)
            for sg in response.get("SecurityGroups", []):
                for rule in sg.get("IpPermissions", []):
                    is_public = any(
                        r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
                    )
                    if not is_public:
                        continue

                    protocol = rule.get("IpProtocol", "")
                    if protocol == "-1":
                        # All traffic — add a wide range
                        open_ports.update(range(1, 65536))
                    else:
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 0)
                        open_ports.update(range(from_port, to_port + 1))
        except Exception:
            pass
        return open_ports
