import json

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class SSMCollector(BaseCollector):
    service_name = "ssm"

    def collect(self):
        client = self.session.client("ssm")
        paginator = client.get_paginator("describe_parameters")

        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                name = param["Name"]
                param_type = param.get("Type", "")
                if param_type == "SecureString":
                    continue
                try:
                    result = self._collect_parameter(client, name, param_type)
                    if result:
                        yield result
                except Exception as e:
                    out.error(f"SSM {name}: {e}")

    def _collect_parameter(self, client, name, param_type):
        response = client.get_parameter(Name=name)
        param = response["Parameter"]

        output = {
            "name": name,
            "type": param_type,
            "value": param.get("Value", ""),
            "version": param.get("Version"),
            "lastModifiedDate": str(param.get("LastModifiedDate", "")),
        }

        safe_name = name.lstrip("/").replace("/", "_")
        path = self.write_file(safe_name, json.dumps(output, indent=2), ext="json")
        out.status(f"Collected SSM parameter {name} ({param_type})")
        return (f"ssm_{safe_name}", path)
