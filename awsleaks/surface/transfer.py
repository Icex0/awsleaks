from awsleaks.surface.base import BaseCheck


class TransferCheck(BaseCheck):
    name = "transfer"

    def run(self):
        client = self.session.client("transfer")
        next_token = None

        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            response = client.list_servers(**kwargs)

            for server in response.get("Servers", []):
                server_id = server.get("ServerId", "")
                endpoint_type = server.get("EndpointType", "")

                if endpoint_type != "PUBLIC":
                    continue

                try:
                    self._check_server(client, server_id)
                except Exception:
                    pass

            next_token = response.get("NextToken")
            if not next_token:
                break

    def _check_server(self, client, server_id):
        server = client.describe_server(ServerId=server_id).get("Server", {})
        protocols = server.get("Protocols", [])
        identity_type = server.get("IdentityProviderType", "")
        region = self.session.region_name or "us-east-1"
        endpoint = f"{server_id}.server.transfer.{region}.amazonaws.com"

        ports = []
        for proto in protocols:
            if proto == "SFTP":
                ports.append("22")
            elif proto == "FTPS":
                ports.append("990")
            elif proto == "FTP":
                ports.append("21")

        detail = f"EXPOSED | Endpoint: {endpoint} | Protocols: {', '.join(protocols)} | Auth: {identity_type}"

        self.add_finding(
            resource=f"{server_id} (Transfer Family)",
            detail=detail,
            severity="HIGH",
            target=endpoint,
            ports=ports if ports else None,
        )
