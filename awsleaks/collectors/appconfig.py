from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class AppConfigCollector(BaseCollector):
    service_name = "appconfig"

    def collect(self):
        client = self.session.client("appconfig")

        apps = client.list_applications().get("Items", [])
        for app in apps:
            app_id = app["Id"]
            app_name = app.get("Name", app_id)
            try:
                yield from self._collect_app(client, app_id, app_name)
            except Exception as e:
                out.error(f"AppConfig {app_name}: {e}")

    def _collect_app(self, client, app_id, app_name):
        profiles = client.list_configuration_profiles(
            ApplicationId=app_id
        ).get("Items", [])

        for profile in profiles:
            profile_id = profile["Id"]
            profile_name = profile.get("Name", profile_id)

            # Only hosted configs have content we can retrieve
            if profile.get("Type") != "AWS.AppConfig.FeatureFlags" and profile.get("LocationUri", "") != "hosted":
                # Try to get hosted config versions
                pass

            try:
                versions = client.list_hosted_configuration_versions(
                    ApplicationId=app_id,
                    ConfigurationProfileId=profile_id,
                ).get("Items", [])

                if not versions:
                    continue

                # Get the latest version
                latest = max(versions, key=lambda v: v.get("VersionNumber", 0))
                version_num = latest["VersionNumber"]

                response = client.get_hosted_configuration_version(
                    ApplicationId=app_id,
                    ConfigurationProfileId=profile_id,
                    VersionNumber=version_num,
                )
                content = response["Content"].read().decode("utf-8", errors="replace")

                safe_name = f"{app_name}_{profile_name}".replace("/", "_").replace(" ", "_")
                content_type = response.get("ContentType", "application/json")
                ext = "json" if "json" in content_type else "yaml" if "yaml" in content_type else "txt"

                path = self.write_file(safe_name, content, ext=ext)
                out.status(f"Collected AppConfig {app_name}/{profile_name}")
                yield (f"appconfig_{safe_name}", path)

            except Exception as e:
                out.error(f"AppConfig {app_name}/{profile_name}: {e}")
