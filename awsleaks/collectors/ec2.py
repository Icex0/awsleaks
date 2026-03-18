import base64
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class EC2Collector(BaseCollector):
    service_name = "ec2"

    def collect(self):
        client = self.session.client("ec2")
        paginator = client.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    try:
                        result = self._collect_user_data(client, instance_id)
                        if result:
                            yield result
                    except Exception as e:
                        out.error(f"EC2 {instance_id}: {e}")

        # Also check launch templates
        yield from self._collect_launch_templates(client)

    def _collect_user_data(self, client, instance_id):
        response = client.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute="userData",
        )
        user_data = response.get("UserData", {}).get("Value")
        if not user_data:
            return None

        decoded = base64.b64decode(user_data).decode("utf-8", errors="replace")
        path = self.write_file(instance_id, decoded, ext="sh")
        out.status(f"Collected EC2 user data {instance_id}")
        return (f"ec2_{instance_id}", path)

    def _collect_launch_templates(self, client):
        paginator = client.get_paginator("describe_launch_templates")
        for page in paginator.paginate():
            for lt in page.get("LaunchTemplates", []):
                lt_id = lt["LaunchTemplateId"]
                lt_name = lt["LaunchTemplateName"]
                try:
                    response = client.describe_launch_template_versions(
                        LaunchTemplateId=lt_id,
                        Versions=["$Latest"],
                    )
                    for version in response.get("LaunchTemplateVersions", []):
                        user_data = version.get("LaunchTemplateData", {}).get("UserData")
                        if user_data:
                            decoded = base64.b64decode(user_data).decode("utf-8", errors="replace")
                            path = self.write_file(f"lt_{lt_name}", decoded, ext="sh")
                            out.status(f"Collected launch template {lt_name}")
                            yield (f"lt_{lt_name}", path)
                except Exception as e:
                    out.error(f"Launch template {lt_name}: {e}")
