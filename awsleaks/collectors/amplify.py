import json
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class AmplifyCollector(BaseCollector):
    service_name = "amplify"

    def collect(self):
        client = self.session.client("amplify")

        apps = client.list_apps().get("apps", [])
        for app in apps:
            app_id = app["appId"]
            app_name = app.get("name", app_id)
            try:
                yield self._collect_app(client, app, app_name)
            except Exception as e:
                out.error(f"Amplify {app_name}: {e}")

            # Per-branch env vars and config
            try:
                branches = client.list_branches(appId=app_id).get("branches", [])
                for branch in branches:
                    result = self._collect_branch(branch, app_name)
                    if result:
                        yield result
            except Exception as e:
                out.error(f"Amplify {app_name} branches: {e}")

    def _collect_app(self, client, app, app_name):
        app_dir = os.path.join(self.output_dir, app_name)
        os.makedirs(app_dir, exist_ok=True)

        # Write env vars
        env_vars = app.get("environmentVariables", {})
        if env_vars:
            env_path = os.path.join(app_dir, "environment_variables.json")
            if not os.path.exists(env_path):
                with open(env_path, "w") as f:
                    json.dump(env_vars, f, indent=2)

        # Write buildSpec
        build_spec = app.get("buildSpec", "")
        if build_spec:
            spec_path = os.path.join(app_dir, "buildspec.yml")
            if not os.path.exists(spec_path):
                with open(spec_path, "w") as f:
                    f.write(build_spec)

        out.status(f"Collected Amplify app {app_name}")
        return (f"amplify_{app_name}", app_dir)

    def _collect_branch(self, branch, app_name):
        branch_name = branch.get("branchName", "unknown")
        env_vars = branch.get("environmentVariables", {})
        if not env_vars:
            return None

        safe_branch = branch_name.replace("/", "_")
        branch_dir = os.path.join(self.output_dir, app_name, f"branch_{safe_branch}")
        os.makedirs(branch_dir, exist_ok=True)

        env_path = os.path.join(branch_dir, "environment_variables.json")
        if not os.path.exists(env_path):
            with open(env_path, "w") as f:
                json.dump(env_vars, f, indent=2)

        out.status(f"Collected Amplify branch {app_name}/{branch_name}")
        return (f"amplify_{app_name}_{safe_branch}", branch_dir)
