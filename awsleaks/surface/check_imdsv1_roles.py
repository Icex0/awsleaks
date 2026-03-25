from awsleaks.surface.base import BaseCheck
from awsleaks import output as out
from awsleaks.surface.privesc_paths import (
    SOLO_PRIVESC,
    PASSROLE_COMBOS,
    OTHER_COMBOS,
    STS_PRIVESC,
)


def _extract_actions_from_policy(policy_doc):
    """Extract all allowed actions from a policy document."""
    actions = set()
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        stmt_actions = stmt.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        for action in stmt_actions:
            actions.add(action)
    return actions


def _extract_passrole_resources(policy_doc):
    """Extract Resource values from statements that grant iam:PassRole."""
    resources = []
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        stmt_actions = stmt.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        # Check if this statement grants PassRole (or wildcard)
        grants_passrole = False
        for action in stmt_actions:
            if action == "*":
                grants_passrole = True
                break
            if ":" not in action:
                continue
            svc, api = action.split(":", 1)
            if svc.lower() == "iam" and (api == "*" or api.lower() == "passrole"):
                grants_passrole = True
                break
        if not grants_passrole:
            continue
        stmt_resources = stmt.get("Resource", [])
        if isinstance(stmt_resources, str):
            stmt_resources = [stmt_resources]
        resources.extend(stmt_resources)
    return resources


def _action_matches(actions, required_action):
    """Check if any action in the set matches the required action (with wildcard support)."""
    if "*" in actions:
        return True
    service, api = required_action.split(":", 1)
    for a in actions:
        if a == "*":
            return True
        if ":" not in a:
            continue
        a_service, a_api = a.split(":", 1)
        if a_service.lower() == service.lower():
            if a_api == "*" or a_api.lower() == api.lower():
                return True
    return False


def _check_privesc(actions, passrole_resources=None):
    """Check a set of IAM actions against all privesc categories. Returns list of findings."""
    findings = []
    passrole_resources = passrole_resources or []

    # Determine PassRole scope
    passrole_unrestricted = any(r == "*" for r in passrole_resources)
    if passrole_resources:
        if passrole_unrestricted:
            passrole_scope = "PassRole Resource: * (UNRESTRICTED — can pass ANY role)"
        else:
            passrole_scope = "PassRole Resource: " + ", ".join(passrole_resources) + " (scoped)"
    else:
        passrole_scope = None

    # Solo permissions — single permission enough for escalation
    for perm in SOLO_PRIVESC:
        if _action_matches(actions, perm):
            findings.append(("Solo", perm, f"Direct privesc via {perm}"))

    # PassRole combinations
    for required_set in PASSROLE_COMBOS:
        if all(_action_matches(actions, p) for p in required_set):
            perms_str = " + ".join(sorted(required_set))
            desc = passrole_scope or ""
            findings.append(("PassRole", perms_str, desc))

    # Other multi-permission combos (no PassRole)
    for required_set in OTHER_COMBOS:
        if all(_action_matches(actions, p) for p in required_set):
            perms_str = " + ".join(sorted(required_set))
            findings.append(("Combo", perms_str, ""))

    # STS — assume role
    for perm in STS_PRIVESC:
        if _action_matches(actions, perm):
            findings.append(("STS", perm, "Assume other roles (check trust policies)"))

    return findings


class IMDSv1RoleCheck(BaseCheck):
    name = "imdsv1-roles"

    note = None  # Custom print_findings handles notes

    def __init__(self, session):
        super().__init__(session)
        self.include_private = False

    def print_findings(self):
        if not self.findings:
            out.none("No exposed resources found")
            return

        out.caution(f"{len(self.findings)} IMDSv1 instance(s) vulnerable to SSRF-based credential theft via the metadata endpoint")
        out.detail("Check https://github.com/DataDog/pathfinding.cloud for more details on exploitation requirements")
        print()

        for f in self.findings:
            if f.get("severity") == "MEDIUM":
                out.caution(f['resource'])
            else:
                out.warn(f['resource'])
            out.detail(f['detail'])

    def _is_publicly_exposed(self, instance, ec2_client, sg_cache):
        """Check if instance has a public IP and security groups open to the internet."""
        public_ip = instance.get("PublicIpAddress")
        if not public_ip:
            return False, None, []

        sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        open_ports = []

        for sg_id in sg_ids:
            if sg_id not in sg_cache:
                response = ec2_client.describe_security_groups(GroupIds=[sg_id])
                sg_cache[sg_id] = response.get("SecurityGroups", [{}])[0]

            sg = sg_cache[sg_id]
            for rule in sg.get("IpPermissions", []):
                is_open = False
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        is_open = True
                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        is_open = True

                if not is_open:
                    continue

                protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)

                if protocol == "-1":
                    open_ports.append("ALL")
                elif from_port == to_port:
                    open_ports.append(str(from_port))
                else:
                    open_ports.append(f"{from_port}-{to_port}")

        if not open_ports:
            return False, public_ip, []

        open_ports = sorted(set(open_ports),
                            key=lambda x: (x != "ALL", int(x.split("-")[0]) if x != "ALL" else 0))
        return True, public_ip, open_ports

    def run(self):
        ec2_client = self.session.client("ec2")
        iam_client = self.session.client("iam")
        seen_roles = {}
        sg_cache = {}

        paginator = ec2_client.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped", "stopping"]}]
        ):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    metadata_options = instance.get("MetadataOptions", {})
                    if metadata_options.get("HttpTokens") == "required":
                        continue

                    instance_state = instance.get("State", {}).get("Name", "unknown")

                    # Non-running instances can't be publicly exposed right now,
                    # but still worth flagging since they retain their config
                    is_public = False
                    public_ip = None
                    open_ports = []
                    if instance_state == "running":
                        is_public, public_ip, open_ports = self._is_publicly_exposed(
                            instance, ec2_client, sg_cache
                        )

                    # Default: only show publicly exposed running instances
                    if not self.include_private and not is_public:
                        continue

                    instance_id = instance["InstanceId"]
                    name_tag = next(
                        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                        "",
                    )
                    profile = instance.get("IamInstanceProfile")
                    http_tokens = metadata_options.get("HttpTokens", "optional")

                    resource = f"{instance_id} ({name_tag})" if name_tag else instance_id
                    detail_parts = [f"IMDSv1 enabled (HttpTokens: {http_tokens})"]

                    if instance_state != "running":
                        detail_parts.append(f"State: {instance_state.upper()}")
                    if is_public:
                        detail_parts.append(f"PUBLIC | IP: {public_ip} | Ports: {', '.join(open_ports)}")
                    elif instance_state == "running":
                        detail_parts.append("PRIVATE (no public exposure)")

                    if not profile:
                        detail_parts.append("No IAM role attached")
                        self.add_finding(resource=resource, detail=" | ".join(detail_parts), severity="MEDIUM")
                        continue

                    # Resolve instance profile -> role
                    profile_name = profile["Arn"].split("/")[-1]
                    if profile_name not in seen_roles:
                        profile_detail = iam_client.get_instance_profile(
                            InstanceProfileName=profile_name
                        )
                        seen_roles[profile_name] = profile_detail["InstanceProfile"].get("Roles", [])

                    roles = seen_roles[profile_name]
                    if not roles:
                        detail_parts.append("Instance profile has no roles")
                        self.add_finding(resource=resource, detail=" | ".join(detail_parts), severity="MEDIUM")
                        continue

                    for role in roles:
                        role_name = role["RoleName"]
                        detail_parts.append(f"Role: {role_name}")

                        # Get all policies and extract actions + PassRole resource scope
                        all_actions = set()
                        passrole_resources = []

                        inline = iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]
                        for policy_name in inline:
                            doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            all_actions |= _extract_actions_from_policy(doc["PolicyDocument"])
                            passrole_resources.extend(_extract_passrole_resources(doc["PolicyDocument"]))

                        managed = iam_client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
                        for policy in managed:
                            policy_arn = policy["PolicyArn"]
                            version_id = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                            doc = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                            all_actions |= _extract_actions_from_policy(doc["PolicyVersion"]["Document"])
                            passrole_resources.extend(_extract_passrole_resources(doc["PolicyVersion"]["Document"]))

                        # Check for privesc paths
                        privesc_findings = _check_privesc(all_actions, passrole_resources)
                        if privesc_findings:
                            paths = [f"[{cat}] {perms}" + (f" — {desc}" if desc else "") for cat, perms, desc in privesc_findings]
                            detail_parts.append(f"PRIVESC RISK — {len(privesc_findings)} path(s): " + "; ".join(paths))
                            self.add_finding(resource=resource, detail=" | ".join(detail_parts), severity="HIGH")
                        else:
                            detail_parts.append("No known privesc paths")
                            self.add_finding(resource=resource, detail=" | ".join(detail_parts), severity="MEDIUM")
