import os
import zipfile

import requests

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class LambdaCollector(BaseCollector):
    service_name = "lambda"

    def collect(self):
        client = self.session.client("lambda")
        paginator = client.get_paginator("list_functions")

        for page in paginator.paginate():
            for fn in page["Functions"]:
                name = fn["FunctionName"]
                try:
                    yield self._download_and_extract(client, name)
                except Exception as e:
                    out.error(f"Lambda {name}: {e}")

    def _download_and_extract(self, client, name):
        zip_path = os.path.join(self.output_dir, f"{name}.zip")
        extract_path = os.path.join(self.output_dir, name)

        if not os.path.exists(zip_path):
            response = client.get_function(FunctionName=name)
            url = response["Code"]["Location"]
            out.status(f"Downloading Lambda {name}")
            r = requests.get(url)
            with open(zip_path, "wb") as f:
                f.write(r.content)

        if not os.path.exists(extract_path):
            os.makedirs(extract_path, exist_ok=True)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_path)

        return (f"lambda_{name}", extract_path)
