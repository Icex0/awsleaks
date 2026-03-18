import json

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class SSMDocumentCollector(BaseCollector):
    service_name = "ssm-documents"

    def collect(self):
        client = self.session.client("ssm")
        paginator = client.get_paginator("list_documents")

        for page in paginator.paginate(
            Filters=[{"Key": "Owner", "Values": ["Self"]}]
        ):
            for doc in page.get("DocumentIdentifiers", []):
                name = doc.get("Name", "")
                try:
                    result = self._collect_document(client, name)
                    if result:
                        yield result
                except Exception as e:
                    out.error(f"SSM Document {name}: {e}")

    def _collect_document(self, client, name):
        response = client.get_document(Name=name)
        content = response.get("Content", "")
        doc_type = response.get("DocumentType", "")
        doc_format = response.get("DocumentFormat", "Text")

        ext = "json" if doc_format == "JSON" else "yaml" if doc_format == "YAML" else "txt"

        safe_name = name.replace("/", "_").replace(":", "_")
        path = self.write_file(safe_name, content, ext=ext)
        out.status(f"Collected SSM document {name} ({doc_type})")
        return (f"ssm_doc_{safe_name}", path)
