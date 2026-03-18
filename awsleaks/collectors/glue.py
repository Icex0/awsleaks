import os

import requests

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class GlueCollector(BaseCollector):
    service_name = "glue"

    def collect(self):
        client = self.session.client("glue")
        paginator = client.get_paginator("get_jobs")

        for page in paginator.paginate():
            for job in page.get("Jobs", []):
                name = job["Name"]
                try:
                    yield from self._collect_job(client, job)
                except Exception as e:
                    out.error(f"Glue {name}: {e}")

    def _collect_job(self, client, job):
        name = job["Name"]
        job_dir = os.path.join(self.output_dir, name)
        os.makedirs(job_dir, exist_ok=True)

        # Download the script from S3
        script_location = job.get("Command", {}).get("ScriptLocation", "")
        if script_location:
            script_path = os.path.join(job_dir, "script.py")
            if not os.path.exists(script_path):
                out.status(f"Downloading Glue job script {name}")
                s3 = self.session.client("s3")
                bucket, key = self._parse_s3_uri(script_location)
                s3.download_file(bucket, key, script_path)

        # Also dump extra py files and jar references
        extra_files = job.get("DefaultArguments", {}).get("--extra-py-files", "")
        if extra_files:
            extras_path = os.path.join(job_dir, "extra_py_files.txt")
            if not os.path.exists(extras_path):
                with open(extras_path, "w") as f:
                    f.write(extra_files)

        yield (f"glue_{name}", job_dir)

    @staticmethod
    def _parse_s3_uri(uri):
        path = uri.replace("s3://", "")
        bucket, _, key = path.partition("/")
        return bucket, key
