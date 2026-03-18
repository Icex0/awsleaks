import json

from awsleaks.surface.base import BaseCheck


class OpenSearchCheck(BaseCheck):
    name = "opensearch"

    def run(self):
        client = self.session.client("opensearch")
        domains = client.list_domain_names().get("DomainNames", [])

        if not domains:
            return

        domain_names = [d["DomainName"] for d in domains]

        for i in range(0, len(domain_names), 5):
            batch = domain_names[i:i + 5]
            response = client.describe_domains(DomainNames=batch)

            for domain in response.get("DomainStatusList", []):
                name = domain.get("DomainName", "")
                endpoint = domain.get("Endpoint") or domain.get("Endpoints", {}).get("vpc", "")

                # VPC-bound domains use SGs, not public
                vpc_options = domain.get("VPCOptions", {})
                if vpc_options.get("VPCId"):
                    continue

                if not endpoint:
                    continue

                # Check fine-grained access control
                advanced = domain.get("AdvancedSecurityOptions", {})
                fgac = advanced.get("Enabled", False)
                internal_db = advanced.get("InternalUserDatabaseEnabled", False)

                restrictions = self._get_restrictions(domain)
                url = f"https://{endpoint}"

                parts = [url]

                if fgac:
                    auth = "Fine-grained access control: internal user DB" if internal_db else "Fine-grained access control: SAML/IAM"
                    if restrictions:
                        detail = f"Restricted | {url} | {auth} | {' | '.join(restrictions)}"
                    else:
                        detail = f"Public endpoint | {url} | {auth}"
                elif restrictions:
                    detail = f"Restricted | {url} | {' | '.join(restrictions)}"
                else:
                    detail = f"EXPOSED | {url} | No access policy or auth"

                self.add_finding(resource=name, detail=detail, severity="CRITICAL")

    def _get_restrictions(self, domain):
        restrictions = []
        try:
            policy_str = domain.get("AccessPolicies", "{}")
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                condition = stmt.get("Condition", {})

                # Check if principal is restricted (no wildcard)
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
