import json

from awsleaks.surface.base import BaseCheck


class SQSCheck(BaseCheck):
    name = "sqs"

    def run(self):
        client = self.session.client("sqs")
        queues = client.list_queues().get("QueueUrls", [])

        for queue_url in queues:
            try:
                attrs = client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=["Policy"],
                ).get("Attributes", {})

                policy_str = attrs.get("Policy", "")
                if not policy_str:
                    continue

                policy = json.loads(policy_str)
                queue_name = queue_url.split("/")[-1]

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
                        # SourceAccount/SourceOwner matching own account = not public
                        own_account = queue_url.split("/")[-2] if "/" in queue_url else ""
                        is_self_only = any(
                            ("SourceAccount" in key or "SourceOwner" in key) and val == own_account
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
                        detail = f"Restricted | URL: {queue_url} | Actions: {', '.join(actions)} | {' | '.join(restrictions)}"
                    else:
                        detail = f"EXPOSED | URL: {queue_url} | Actions: {', '.join(actions)}"

                    self.add_finding(resource=queue_name, detail=detail)
                    break

            except Exception:
                continue
