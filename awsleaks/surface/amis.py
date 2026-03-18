from awsleaks.surface.base import BaseCheck


class AMICheck(BaseCheck):
    name = "amis"

    def run(self):
        client = self.session.client("ec2")

        images = client.describe_images(
            Owners=["self"],
            Filters=[{"Name": "is-public", "Values": ["true"]}],
        ).get("Images", [])

        for image in images:
            image_id = image["ImageId"]
            name = image.get("Name", "")

            # Check encryption on block devices
            encrypted = all(
                bdm.get("Ebs", {}).get("Encrypted", False)
                for bdm in image.get("BlockDeviceMappings", [])
                if "Ebs" in bdm
            )

            resource = f"{image_id} ({name})" if name else image_id

            if encrypted:
                detail = f"Public but encrypted (KMS key required) | {name}"
            else:
                detail = f"EXPOSED | Public & unencrypted AMI | {name}"

            self.add_finding(resource=resource, detail=detail)
