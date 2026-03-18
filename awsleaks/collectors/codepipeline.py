import json
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class CodePipelineCollector(BaseCollector):
    service_name = "codepipeline"

    def collect(self):
        client = self.session.client("codepipeline")
        paginator = client.get_paginator("list_pipelines")

        for page in paginator.paginate():
            for pipeline_summary in page.get("pipelines", []):
                name = pipeline_summary["name"]
                try:
                    yield self._collect_pipeline(client, name)
                except Exception as e:
                    out.error(f"CodePipeline {name}: {e}")

    def _collect_pipeline(self, client, name):
        response = client.get_pipeline(name=name)
        pipeline = response.get("pipeline", {})

        path = self.write_file(name, json.dumps(pipeline, indent=2, default=str), ext="json")
        out.status(f"Collected CodePipeline {name}")
        return (f"codepipeline_{name}", path)
