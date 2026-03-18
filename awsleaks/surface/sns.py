import json

from awsleaks.surface.base import BaseCheck


class SNSCheck(BaseCheck):
    name = "sns"

    def run(self):
        client = self.session.client("sns")
        paginator = client.get_paginator("list_topics")

        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                topic_arn = topic["TopicArn"]
                topic_name = topic_arn.split(":")[-1]

                try:
                    attrs = client.get_topic_attributes(
                        TopicArn=topic_arn
                    ).get("Attributes", {})

                    policy_str = attrs.get("Policy", "")
                    if not policy_str:
                        continue

                    policy = json.loads(policy_str)

                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue

                        principal = stmt.get("Principal", "")
                        condition = stmt.get("Condition", {})

                        is_public = (
                            principal == "*"
                            or (isinstance(principal, dict) and any(
                                v == "*" or (isinstance(v, list) and "*" in v)
                                for v in principal.values()
                            ))
                        )

                        if not is_public:
                            continue

                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]

                        if condition:
                            # SourceOwner matching own account = not public
                            own_account = topic_arn.split(":")[4]
                            is_self_only = any(
                                ("SourceOwner" in key or "SourceAccount" in key) and val == own_account
                                for op, cond_values in condition.items()
                                if op.startswith("String") and "Not" not in op
                                for key, val in cond_values.items()
                            )
                            if is_self_only:
                                continue
                            restrictions = []
                            for cond_type, cond_values in condition.items():
                                for key, val in cond_values.items():
                                    restrictions.append(f"{key}: {val}")
                            detail = f"Restricted | ARN: {topic_arn} | Actions: {', '.join(actions)} | {' | '.join(restrictions)}"
                        else:
                            detail = f"EXPOSED | ARN: {topic_arn} | Actions: {', '.join(actions)}"

                        self.add_finding(resource=topic_name, detail=detail)
                        break

                except Exception:
                    continue
