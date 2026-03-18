import os
import zipfile

import requests

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class BeanstalkCollector(BaseCollector):
    service_name = "beanstalk"

    def collect(self):
        client = self.session.client("elasticbeanstalk")
        s3 = self.session.client("s3")

        # Collect application versions (source bundles)
        apps = client.describe_applications().get("Applications", [])
        for app in apps:
            app_name = app["ApplicationName"]
            try:
                versions = client.describe_application_versions(
                    ApplicationName=app_name
                ).get("ApplicationVersions", [])

                for version in versions:
                    result = self._collect_version(s3, app_name, version)
                    if result:
                        yield result
            except Exception as e:
                out.error(f"Beanstalk {app_name}: {e}")

        # Also collect environment configs (env vars)
        envs = client.describe_environments().get("Environments", [])
        for env in envs:
            try:
                result = self._collect_env_config(client, env)
                if result:
                    yield result
            except Exception as e:
                out.error(f"Beanstalk env {env.get('EnvironmentName')}: {e}")

    def _collect_version(self, s3, app_name, version):
        version_label = version.get("VersionLabel", "unknown")
        source = version.get("SourceBundle", {})
        bucket = source.get("S3Bucket")
        key = source.get("S3Key")
        if not bucket or not key:
            return None

        safe_label = version_label.replace("/", "_")
        zip_path = os.path.join(self.output_dir, f"{app_name}_{safe_label}.zip")
        extract_path = os.path.join(self.output_dir, f"{app_name}_{safe_label}")

        if not os.path.exists(zip_path):
            out.status(f"Downloading Beanstalk source {app_name}/{version_label}")
            s3.download_file(bucket, key, zip_path)

        if not os.path.exists(extract_path):
            os.makedirs(extract_path, exist_ok=True)
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(extract_path)
            except zipfile.BadZipFile:
                out.error(f"Beanstalk {app_name}/{version_label}: not a valid zip")
                return None

        return (f"beanstalk_{app_name}_{safe_label}", extract_path)

    def _collect_env_config(self, client, env):
        env_name = env["EnvironmentName"]
        settings = client.describe_configuration_settings(
            ApplicationName=env["ApplicationName"],
            EnvironmentName=env_name,
        ).get("ConfigurationSettings", [])

        if not settings:
            return None

        import json
        content = json.dumps(settings, indent=2, default=str)
        path = self.write_file(f"env_{env_name}", content, ext="json")
        out.status(f"Collected Beanstalk env config {env_name}")
        return (f"beanstalk_env_{env_name}", path)
