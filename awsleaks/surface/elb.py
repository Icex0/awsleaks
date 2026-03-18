from awsleaks.surface.base import BaseCheck


class ELBCheck(BaseCheck):
    name = "elb"

    def run(self):
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

                # Get listener ports
                lb_arn = lb.get("LoadBalancerArn", "")
                ports = []
                try:
                    listeners = client.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                    ports = sorted(set(str(l.get("Port", "")) for l in listeners),
                                   key=lambda x: int(x))
                except Exception:
                    pass

                port_str = ", ".join(ports) if ports else "unknown"
                self.add_finding(
                    resource=f"{name} ({lb_type})",
                    detail=f"Internet-facing | DNS: {dns} | Ports: {port_str}",
                    target=dns,
                    ports=ports,
                )

    def _check_classic(self):
        client = self.session.client("elb")
        lbs = client.describe_load_balancers().get("LoadBalancerDescriptions", [])

        for lb in lbs:
            if lb.get("Scheme") != "internet-facing":
                continue

            name = lb.get("LoadBalancerName", "")
            dns = lb.get("DNSName", "")
            ports = sorted(set(str(l.get("LoadBalancerPort", ""))
                               for l in lb.get("ListenerDescriptions", [])),
                           key=lambda x: int(x))

            port_str = ", ".join(ports) if ports else "unknown"
            self.add_finding(
                resource=f"{name} (classic)",
                detail=f"Internet-facing | DNS: {dns} | Ports: {port_str}",
                target=dns,
                ports=ports,
            )
