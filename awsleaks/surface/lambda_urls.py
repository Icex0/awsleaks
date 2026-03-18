import json

from awsleaks.surface.base import BaseCheck


class LambdaURLCheck(BaseCheck):
    name = "lambda-urls"

    def run(self):
        client = self.session.client("lambda")
        paginator = client.get_paginator("list_functions")

        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn["FunctionName"]
                try:
                    url_config = client.get_function_url_config(FunctionName=name)
                except client.exceptions.ResourceNotFoundException:
                    continue

                auth_type = url_config.get("AuthType", "")
                url = url_config.get("FunctionUrl", "")
                cors = url_config.get("Cors", {})

                restrictions = self._get_restrictions(client, name)

                if restrictions:
                    detail = f"Restricted | URL: {url} | Auth: {auth_type} | {' | '.join(restrictions)}"
                else:
                    detail = f"EXPOSED | URL: {url} | Auth: {auth_type}"

                if cors:
                    allow_origins = cors.get("AllowOrigins", [])
                    if "*" in allow_origins:
                        detail += " | CORS: * (all origins)"

                self.add_finding(resource=name, detail=detail, severity="CRITICAL")

    def _get_restrictions(self, client, function_name):
        restrictions = []
        try:
            policy_str = client.get_policy(FunctionName=function_name).get("Policy", "{}")
            policy = json.loads(policy_str)
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
        except client.exceptions.ResourceNotFoundException:
            pass
        except Exception:
            pass
        return restrictions
