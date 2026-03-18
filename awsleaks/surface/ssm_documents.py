from awsleaks.surface.base import BaseCheck
from awsleaks import output as out


class SSMDocumentCheck(BaseCheck):
    name = "ssm-documents"

    def run(self):
        client = self.session.client("ssm")
        paginator = client.get_paginator("list_documents")

        for page in paginator.paginate(
            Filters=[{"Key": "Owner", "Values": ["Self"]}]
        ):
            for doc in page.get("DocumentIdentifiers", []):
                name = doc.get("Name", "")
                try:
                    self._check_document(client, name)
                except Exception as e:
                    out.error(f"SSM Document {name}: {e}")

    def _check_document(self, client, name):
        response = client.describe_document_permission(
            Name=name, PermissionType="Share"
        )
        account_ids = response.get("AccountIds", [])
        account_sharing = response.get("AccountSharingInfoList", [])

        if "all" in account_ids:
            self.add_finding(
                resource=name,
                detail=f"PUBLIC | Document shared with all AWS accounts",
            )
        elif account_ids:
            shared_with = ", ".join(account_ids)
            self.add_finding(
                resource=name,
                detail=f"Shared with accounts: {shared_with}",
            )
