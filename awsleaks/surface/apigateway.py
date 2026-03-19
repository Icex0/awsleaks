import json

from awsleaks.surface.base import BaseCheck


class APIGatewayCheck(BaseCheck):
    name = "apigateway"
    note = "API Gateway endpoints are designed to be public. Review resource policies for restrictions."

    def run(self):
        self._check_rest_apis()
        self._check_http_apis()

    def _check_rest_apis(self):
        client = self.session.client("apigateway")
        apis = client.get_rest_apis().get("items", [])

        for api in apis:
            api_id = api["id"]
            api_name = api.get("name", api_id)
            endpoint_type = api.get("endpointConfiguration", {}).get("types", [])

            if "PRIVATE" in endpoint_type:
                continue

            restrictions = self._get_restrictions(api)

            stages = client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                stage_name = stage.get("stageName", "")
                region = self.session.region_name or "us-east-1"
                url = f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage_name}"

                if restrictions:
                    detail = f"Restricted | Stage: {stage_name} | Type: {', '.join(endpoint_type)} | URL: {url} | {' | '.join(restrictions)}"
                else:
                    detail = f"EXPOSED | Stage: {stage_name} | Type: {', '.join(endpoint_type)} | URL: {url}"

                self.add_finding(
                    resource=f"{api_name} (REST)",
                    detail=detail,
                    severity="CRITICAL",
                )

    def _check_http_apis(self):
        client = self.session.client("apigatewayv2")
        apis = client.get_apis().get("Items", [])

        for api in apis:
            api_name = api.get("Name", api.get("ApiId", ""))
            endpoint = api.get("ApiEndpoint", "")
            protocol = api.get("ProtocolType", "")

            self.add_finding(
                resource=f"{api_name} ({protocol})",
                detail=f"EXPOSED | Endpoint: {endpoint}",
                severity="CRITICAL",
            )

    def _get_restrictions(self, api):
        restrictions = []
        try:
            policy_str = api.get("policy", "")
            if not policy_str:
                return []
            # API Gateway returns policy as escaped JSON string
            policy = json.loads(policy_str.replace("\\", ""))
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                condition = stmt.get("Condition", {})

                is_wildcard = (
                    principal == "*"
                    or (isinstance(principal, dict) and any(
                        v == "*" or (isinstance(v, list) and "*" in v)
                        for v in principal.values()
                    ))
                )
                if not is_wildcard:
                    if isinstance(principal, dict):
                        principal = ", ".join(f"{k}: {v}" for k, v in principal.items())
                    restrictions.append(f"Principal: {principal}")

                if condition:
                    for cond_type, cond_values in condition.items():
                        for key, val in cond_values.items():
                            restrictions.append(f"{key}: {val}")
        except Exception:
            pass
        return restrictions
