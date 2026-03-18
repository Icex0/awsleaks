import json
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class SageMakerCollector(BaseCollector):
    service_name = "sagemaker"

    def collect(self):
        client = self.session.client("sagemaker")
        s3 = self.session.client("s3")

        # Collect notebook instance lifecycle configs (startup scripts)
        paginator = client.get_paginator("list_notebook_instances")
        for page in paginator.paginate():
            for nb in page.get("NotebookInstances", []):
                name = nb["NotebookInstanceName"]
                try:
                    result = self._collect_notebook(client, name)
                    if result:
                        yield result
                except Exception as e:
                    out.error(f"SageMaker notebook {name}: {e}")

        # Collect lifecycle configurations (contain shell scripts)
        lc_paginator = client.get_paginator("list_notebook_instance_lifecycle_configs")
        for page in lc_paginator.paginate():
            for lc in page.get("NotebookInstanceLifecycleConfigs", []):
                lc_name = lc["NotebookInstanceLifecycleConfigName"]
                try:
                    result = self._collect_lifecycle_config(client, lc_name)
                    if result:
                        yield result
                except Exception as e:
                    out.error(f"SageMaker lifecycle {lc_name}: {e}")

    def _collect_notebook(self, client, name):
        response = client.describe_notebook_instance(NotebookInstanceName=name)
        output = {
            "name": name,
            "roleArn": response.get("RoleArn"),
            "lifecycleConfigName": response.get("LifecycleConfigName"),
            "defaultCodeRepository": response.get("DefaultCodeRepository"),
            "additionalCodeRepositories": response.get("AdditionalCodeRepositories", []),
            "kmsKeyId": response.get("KmsKeyId"),
        }

        path = self.write_file(f"notebook_{name}", json.dumps(output, indent=2), ext="json")
        out.status(f"Collected SageMaker notebook {name}")
        return (f"sagemaker_nb_{name}", path)

    def _collect_lifecycle_config(self, client, name):
        import base64

        response = client.describe_notebook_instance_lifecycle_config(
            NotebookInstanceLifecycleConfigName=name
        )

        lc_dir = os.path.join(self.output_dir, f"lifecycle_{name}")
        os.makedirs(lc_dir, exist_ok=True)

        for hook_type in ["OnCreate", "OnStart"]:
            scripts = response.get(hook_type, [])
            for i, script in enumerate(scripts):
                content = base64.b64decode(script["Content"]).decode("utf-8", errors="replace")
                script_path = os.path.join(lc_dir, f"{hook_type}_{i}.sh")
                if not os.path.exists(script_path):
                    with open(script_path, "w") as f:
                        f.write(content)

        out.status(f"Collected SageMaker lifecycle config {name}")
        return (f"sagemaker_lc_{name}", lc_dir)
