import json

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class BatchCollector(BaseCollector):
    service_name = "batch"

    def collect(self):
        client = self.session.client("batch")
        paginator = client.get_paginator("describe_job_definitions")

        for page in paginator.paginate(status="ACTIVE"):
            for job_def in page.get("jobDefinitions", []):
                name = job_def.get("jobDefinitionName", "unknown")
                revision = job_def.get("revision", 0)
                try:
                    yield self._collect_job_def(job_def, name, revision)
                except Exception as e:
                    out.error(f"Batch {name}: {e}")

    def _collect_job_def(self, job_def, name, revision):
        container = job_def.get("containerProperties", {})
        output = {
            "jobDefinitionName": name,
            "revision": revision,
            "container": {
                "image": container.get("image"),
                "command": container.get("command", []),
                "environment": container.get("environment", []),
            },
        }

        # Also check node properties for multi-node jobs
        node_props = job_def.get("nodeProperties", {})
        if node_props:
            node_containers = []
            for node in node_props.get("nodeRangeProperties", []):
                c = node.get("container", {})
                node_containers.append({
                    "image": c.get("image"),
                    "command": c.get("command", []),
                    "environment": c.get("environment", []),
                })
            output["nodeContainers"] = node_containers

        safe_name = f"{name}_{revision}"
        path = self.write_file(safe_name, json.dumps(output, indent=2), ext="json")
        out.status(f"Collected Batch job definition {name}:{revision}")
        return (f"batch_{safe_name}", path)
