import json
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class ECSCollector(BaseCollector):
    service_name = "ecs"

    def collect(self):
        client = self.session.client("ecs")
        paginator = client.get_paginator("list_task_definitions")

        for page in paginator.paginate(status="ACTIVE"):
            for arn in page.get("taskDefinitionArns", []):
                try:
                    yield self._collect_task_def(client, arn)
                except Exception as e:
                    out.error(f"ECS {arn}: {e}")

    def _collect_task_def(self, client, arn):
        name = arn.split("/")[-1].replace(":", "_")
        response = client.describe_task_definition(taskDefinition=arn)
        task_def = response["taskDefinition"]

        # Extract container definitions with env vars
        containers = task_def.get("containerDefinitions", [])
        output = {
            "taskDefinitionArn": arn,
            "containers": [],
        }

        for container in containers:
            output["containers"].append({
                "name": container.get("name"),
                "image": container.get("image"),
                "environment": container.get("environment", []),
                "command": container.get("command", []),
                "entryPoint": container.get("entryPoint", []),
            })

        path = self.write_file(name, json.dumps(output, indent=2), ext="json")
        out.status(f"Collected ECS task definition {name}")
        return (f"ecs_{name}", path)
