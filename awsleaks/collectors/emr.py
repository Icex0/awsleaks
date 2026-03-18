import json

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class EMRCollector(BaseCollector):
    service_name = "emr"

    def collect(self):
        client = self.session.client("emr")
        paginator = client.get_paginator("list_clusters")

        for page in paginator.paginate(
            ClusterStates=["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]
        ):
            for cluster in page.get("Clusters", []):
                cluster_id = cluster["Id"]
                name = cluster.get("Name", cluster_id)
                try:
                    yield from self._collect_cluster(client, cluster_id, name)
                except Exception as e:
                    out.error(f"EMR {name}: {e}")

    def _collect_cluster(self, client, cluster_id, name):
        desc = client.describe_cluster(ClusterId=cluster_id)["Cluster"]

        # Collect cluster config (includes bootstrap actions, configurations)
        cluster_data = {
            "Name": name,
            "Id": cluster_id,
            "Configurations": desc.get("Configurations", []),
            "BootstrapActions": [],
            "Steps": [],
        }

        # Bootstrap actions
        try:
            ba_pages = client.get_paginator("list_bootstrap_actions")
            for page in ba_pages.paginate(ClusterId=cluster_id):
                for ba in page.get("BootstrapActions", []):
                    cluster_data["BootstrapActions"].append({
                        "Name": ba.get("Name", ""),
                        "ScriptPath": ba.get("ScriptPath", ""),
                        "Args": ba.get("Args", []),
                    })
        except Exception:
            pass

        # Steps
        try:
            step_pages = client.get_paginator("list_steps")
            for page in step_pages.paginate(ClusterId=cluster_id):
                for step in page.get("Steps", []):
                    config = step.get("Config", {})
                    cluster_data["Steps"].append({
                        "Name": step.get("Name", ""),
                        "Jar": config.get("Jar", ""),
                        "Args": config.get("Args", []),
                        "Properties": config.get("Properties", {}),
                    })
        except Exception:
            pass

        content = json.dumps(cluster_data, indent=2)
        safe_name = name.replace("/", "_").replace(" ", "_")
        path = self.write_file(safe_name, content, ext="json")
        out.status(f"Collected EMR cluster {name}")
        yield (f"emr_{safe_name}", path)
