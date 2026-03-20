from awsleaks.surface.base import BaseCheck


class MQCheck(BaseCheck):
    name = "mq"

    def run(self):
        client = self.session.client("mq")
        self._ec2 = self.session.client("ec2")

        next_token = None
        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            response = client.list_brokers(**kwargs)

            for summary in response.get("BrokerSummaries", []):
                broker_id = summary["BrokerId"]
                try:
                    self._check_broker(client, broker_id)
                except Exception:
                    pass

            next_token = response.get("NextToken")
            if not next_token:
                break

    def _check_broker(self, client, broker_id):
        broker = client.describe_broker(BrokerId=broker_id)
        name = broker.get("BrokerName", broker_id)
        engine = broker.get("EngineType", "")

        if not broker.get("PubliclyAccessible", False):
            return

        console_url = ""
        instances = broker.get("BrokerInstances", [])
        if instances:
            console_url = instances[0].get("ConsoleURL", "")

        sg_ids = broker.get("SecurityGroups", [])

        if engine == "RABBITMQ":
            # Public RabbitMQ brokers have no SGs — only auth protects them
            detail = f"EXPOSED | Engine: {engine} | No security groups (auth only) | Console: {console_url}"
            severity = "HIGH"
        elif sg_ids and self._sg_allows_public(sg_ids):
            # Public ActiveMQ with open SG
            detail = f"EXPOSED | Engine: {engine} | SG allows 0.0.0.0/0 | Console: {console_url}"
            severity = "HIGH"
        else:
            # Public ActiveMQ with IP-restricted SG
            detail = f"PubliclyAccessible but SG restricts source IPs | Engine: {engine} | Console: {console_url}"
            severity = "MEDIUM"

        self.add_finding(
            resource=f"{name} ({engine})",
            detail=detail,
            severity=severity,
            target=console_url.replace("https://", "").split(":")[0] if console_url else None,
            ports=["443"] if severity == "HIGH" else None,
        )

    def _sg_allows_public(self, sg_ids):
        response = self._ec2.describe_security_groups(GroupIds=sg_ids)
        for sg in response.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol", "")
                if protocol == "-1" or rule.get("FromPort", 0) <= 443 <= rule.get("ToPort", 0):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            return True
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            return True
        return False
