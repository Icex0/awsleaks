import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class StepFunctionsCollector(BaseCollector):
    service_name = "stepfunctions"

    def collect(self):
        client = self.session.client("stepfunctions")
        paginator = client.get_paginator("list_state_machines")

        for page in paginator.paginate():
            for sm in page.get("stateMachines", []):
                name = sm["name"]
                arn = sm["stateMachineArn"]
                try:
                    yield self._collect_definition(client, name, arn)
                except Exception as e:
                    out.error(f"Step Functions {name}: {e}")

    def _collect_definition(self, client, name, arn):
        response = client.describe_state_machine(stateMachineArn=arn)
        definition = response.get("definition", "")

        path = self.write_file(name, definition, ext="json")
        out.status(f"Collected Step Function {name}")
        return (f"sfn_{name}", path)
