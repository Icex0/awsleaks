import json
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class APIGatewayCollector(BaseCollector):
    service_name = "apigateway"

    def collect(self):
        client = self.session.client("apigateway")

        # REST APIs
        apis = client.get_rest_apis().get("items", [])
        for api in apis:
            api_id = api["id"]
            api_name = api.get("name", api_id)
            try:
                yield from self._collect_api(client, api_id, api_name)
            except Exception as e:
                out.error(f"API Gateway {api_name}: {e}")

    def _collect_api(self, client, api_id, api_name):
        # Collect stage variables
        stages = client.get_stages(restApiId=api_id).get("item", [])
        for stage in stages:
            stage_name = stage.get("stageName", "unknown")
            variables = stage.get("variables", {})
            if not variables:
                continue

            output = {
                "apiId": api_id,
                "apiName": api_name,
                "stageName": stage_name,
                "stageVariables": variables,
            }

            safe_name = f"{api_name}_{stage_name}"
            path = self.write_file(safe_name, json.dumps(output, indent=2), ext="json")
            out.status(f"Collected API Gateway stage vars {api_name}/{stage_name}")
            yield (f"apigw_{safe_name}", path)
