import json

from awsleaks.surface.base import BaseCheck


class ECRCheck(BaseCheck):
    name = "ecr"

    def run(self):
        client = self.session.client("ecr")
        paginator = client.get_paginator("describe_repositories")

        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                repo_name = repo["repositoryName"]
                repo_uri = repo.get("repositoryUri", "")

                try:
                    policy_str = client.get_repository_policy(
                        repositoryName=repo_name
                    ).get("policyText", "{}")
                    policy = json.loads(policy_str)

                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        principal = stmt.get("Principal", "")
                        is_public = (
                            principal == "*"
                            or (isinstance(principal, dict) and any(
                                v == "*" or (isinstance(v, list) and "*" in v)
                                for v in principal.values()
                            ))
                        )

                        if not is_public:
                            continue

                        condition = stmt.get("Condition", {})
                        if condition:
                            restrictions = []
                            for cond_type, cond_values in condition.items():
                                for key, val in cond_values.items():
                                    restrictions.append(f"{key}: {val}")
                            detail = f"Restricted | URI: {repo_uri} | {' | '.join(restrictions)}"
                        else:
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            detail = f"EXPOSED | URI: {repo_uri} | Actions: {', '.join(actions)}"

                        self.add_finding(resource=repo_name, detail=detail)
                        break

                except client.exceptions.RepositoryPolicyNotFoundException:
                    continue
                except Exception:
                    continue
