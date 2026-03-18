import json
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class CodeBuildCollector(BaseCollector):
    service_name = "codebuild"

    def collect(self):
        client = self.session.client("codebuild")

        project_names = []
        paginator = client.get_paginator("list_projects")
        for page in paginator.paginate():
            project_names.extend(page.get("projects", []))

        # batch_get_projects supports max 100 at a time
        for i in range(0, len(project_names), 100):
            batch = project_names[i:i + 100]
            response = client.batch_get_projects(names=batch)
            for project in response.get("projects", []):
                try:
                    result = self._collect_project(project)
                    if result:
                        yield result
                except Exception as e:
                    out.error(f"CodeBuild {project.get('name')}: {e}")

    def _collect_project(self, project):
        name = project["name"]
        output = {
            "name": name,
            "environment": project.get("environment", {}),
            "source": project.get("source", {}),
            "buildspec": project.get("source", {}).get("buildspec", ""),
            "environmentVariables": project.get("environment", {}).get("environmentVariables", []),
            "secondarySources": project.get("secondarySources", []),
        }

        path = self.write_file(name, json.dumps(output, indent=2), ext="json")
        out.status(f"Collected CodeBuild project {name}")
        return (f"codebuild_{name}", path)
