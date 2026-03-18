import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class CloudFormationCollector(BaseCollector):
    service_name = "cloudformation"

    def collect(self):
        client = self.session.client("cloudformation")
        paginator = client.get_paginator("list_stacks")

        for page in paginator.paginate(StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE"]):
            for stack in page.get("StackSummaries", []):
                name = stack["StackName"]
                try:
                    yield self._collect_template(client, name)
                except Exception as e:
                    out.error(f"CloudFormation {name}: {e}")

    def _collect_template(self, client, name):
        response = client.get_template(StackName=name, TemplateStage="Original")
        body = response.get("TemplateBody", "")

        # TemplateBody can be a string or dict
        if isinstance(body, dict):
            import json
            body = json.dumps(body, indent=2)

        ext = "json" if body.lstrip().startswith("{") else "yaml"

        path = self.write_file(name, body, ext=ext)
        out.status(f"Collected CloudFormation stack {name}")
        return (f"cfn_{name}", path)
