import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class CodeCommitCollector(BaseCollector):
    service_name = "codecommit"

    def collect(self):
        client = self.session.client("codecommit")
        paginator = client.get_paginator("list_repositories")

        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = repo["repositoryName"]
                try:
                    result = self._download_repo(client, name)
                    if result:
                        yield result
                except Exception as e:
                    out.error(f"CodeCommit {name}: {e}")

    def _download_repo(self, client, name):
        repo_dir = os.path.join(self.output_dir, name)
        if os.path.exists(repo_dir):
            return (f"codecommit_{name}", repo_dir)

        os.makedirs(repo_dir, exist_ok=True)
        out.status(f"Downloading CodeCommit repo {name}")

        # Get default branch, fall back to listing branches
        repo_meta = client.get_repository(repositoryName=name)
        branch = repo_meta["repositoryMetadata"].get("defaultBranch")
        if not branch:
            branches = client.list_branches(repositoryName=name).get("branches", [])
            if branches:
                branch = branches[0]
            else:
                out.status(f"CodeCommit {name}: empty repo, skipping")
                os.rmdir(repo_dir)
                return None

        # Get the commit tree
        branch_info = client.get_branch(repositoryName=name, branchName=branch)
        commit_id = branch_info["branch"]["commitId"]

        self._download_folder(client, name, commit_id, "/", repo_dir)
        return (f"codecommit_{name}", repo_dir)

    def _download_folder(self, client, repo_name, commit_id, folder_path, local_dir):
        response = client.get_folder(
            repositoryName=repo_name,
            commitSpecifier=commit_id,
            folderPath=folder_path,
        )

        # Download files in this folder
        for file_entry in response.get("files", []):
            file_path = file_entry["absolutePath"]
            local_path = os.path.join(local_dir, file_path.lstrip("/"))
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            file_resp = client.get_file(
                repositoryName=repo_name,
                commitSpecifier=commit_id,
                filePath=file_path,
            )
            with open(local_path, "wb") as f:
                f.write(file_resp["fileContent"])

        # Recurse into subfolders
        for sub in response.get("subFolders", []):
            self._download_folder(client, repo_name, commit_id, sub["absolutePath"], local_dir)
