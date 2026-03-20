import json

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class LightsailCollector(BaseCollector):
    service_name = "lightsail"

    def collect(self):
        client = self.session.client("lightsail")

        try:
            response = client.get_container_services()
        except Exception as e:
            out.error(f"Lightsail: {e}")
            return

        for svc in response.get("containerServices", []):
            try:
                result = self._collect_container_service(svc)
                if result:
                    yield result
            except Exception as e:
                out.error(f"Lightsail {svc.get('containerServiceName')}: {e}")

    def _collect_container_service(self, svc):
        name = svc.get("containerServiceName", "unknown")
        deployment = svc.get("currentDeployment", {})
        containers = deployment.get("containers", {})

        all_env_vars = {}
        for container_name, container in containers.items():
            env = container.get("environment", {})
            if env:
                all_env_vars[container_name] = env

        if not all_env_vars:
            return None

        output = {
            "name": name,
            "containers": all_env_vars,
        }

        path = self.write_file(name, json.dumps(output, indent=2), ext="json")
        out.status(f"Collected Lightsail container service {name}")
        return (f"lightsail_{name}", path)
