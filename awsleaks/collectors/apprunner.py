import json

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class AppRunnerCollector(BaseCollector):
    service_name = "apprunner"

    def collect(self):
        client = self.session.client("apprunner")
        next_token = None
        while True:
            kwargs = {}
            if next_token:
                kwargs["NextToken"] = next_token
            response = client.list_services(**kwargs)
            for svc in response.get("ServiceSummaryList", []):
                try:
                    result = self._collect_service(client, svc["ServiceArn"], svc["ServiceName"])
                    if result:
                        yield result
                except Exception as e:
                    out.error(f"AppRunner {svc['ServiceName']}: {e}")
            next_token = response.get("NextToken")
            if not next_token:
                break

    def _collect_service(self, client, arn, name):
        response = client.describe_service(ServiceArn=arn)
        service = response.get("Service", {})

        source_config = service.get("SourceConfiguration", {})
        image_config = source_config.get("ImageRepository", {}).get("ImageConfiguration", {})
        code_config = source_config.get("CodeRepository", {}).get("CodeConfiguration", {}).get("CodeConfigurationValues", {})

        env_vars = {}
        env_vars.update(image_config.get("RuntimeEnvironmentVariables", {}))
        env_vars.update(code_config.get("RuntimeEnvironmentVariables", {}))

        if not env_vars:
            return None

        output = {
            "name": name,
            "arn": arn,
            "environmentVariables": env_vars,
        }

        path = self.write_file(name, json.dumps(output, indent=2), ext="json")
        out.status(f"Collected AppRunner service {name}")
        return (f"apprunner_{name}", path)
