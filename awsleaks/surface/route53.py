import os
from shutil import which

from awsleaks.surface.base import BaseCheck
from awsleaks import output as out


class Route53Check(BaseCheck):
    name = "route53"
    note = "DNS records are collected for subdomain takeover analysis. Run subjack over the output for takeover detection."

    def run(self):
        client = self.session.client("route53")
        self._domains = []

        # List all hosted zones
        paginator = client.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                if zone.get("Config", {}).get("PrivateZone", False):
                    continue

                zone_id = zone["Id"].split("/")[-1]
                zone_name = zone["Name"].rstrip(".")

                record_paginator = client.get_paginator("list_resource_record_sets")
                for rpage in record_paginator.paginate(HostedZoneId=zone_id):
                    for record in rpage.get("ResourceRecordSets", []):
                        rtype = record.get("Type", "")
                        if rtype not in ("A", "AAAA", "CNAME"):
                            continue
                        name = record["Name"].rstrip(".")
                        # Skip validation/verification records (ACM, DKIM, DMARC, etc.)
                        if name.startswith("_") or "._domainkey." in name:
                            continue
                        self._domains.append(name)

        if self._domains:
            self.add_finding(
                resource=f"Collected {len(self._domains)} DNS records from public hosted zones",
                detail="A/AAAA/CNAME records written to route53_domains.txt for subdomain takeover analysis",
                severity="INFO",
            )

    def print_findings(self):
        if not self._domains:
            out.none("No public DNS records found")
            return

        out.status(f"Collected {len(self._domains)} A/AAAA/CNAME records from public hosted zones")

    def write_domains(self, output_dir, run_subjack=False):
        """Write domains to file and optionally run subjack."""
        if not self._domains:
            return

        os.makedirs(output_dir, exist_ok=True)
        domains_path = os.path.join(output_dir, "route53_domains.txt")
        with open(domains_path, "w") as f:
            for domain in sorted(set(self._domains)):
                f.write(f"{domain}\n")

        unique_count = len(set(self._domains))
        out.status(f"Wrote {unique_count} unique domains to {domains_path}")

        if not run_subjack:
            out.caution("Subdomain takeover scan skipped. Use --subjack to run automatically.")
            print(f"    Or run manually: subjack -w {domains_path} -t 20 -ssl -a")
            return

        # Check for subjack
        subjack_path = which("subjack")
        if subjack_path:
            out.status(f"Found subjack, running subdomain takeover check on {unique_count} domains...")
            results_path = os.path.join(output_dir, "subjack_results.txt")
            import subprocess
            try:
                result = subprocess.run(
                    [subjack_path, "-w", domains_path, "-t", "20",
                     "-o", results_path, "-ssl", "-a"],
                    capture_output=True, text=True, timeout=900,
                )
                if os.path.exists(results_path) and os.path.getsize(results_path) > 0:
                    out.warn(f"Subdomain takeover candidates found! See {results_path}")
                    with open(results_path) as rf:
                        for line in rf:
                            out.detail(line.strip())
                else:
                    out.none("No subdomain takeover candidates found")
            except subprocess.TimeoutExpired:
                out.error("subjack timed out after 15 minutes")
            except Exception as e:
                out.error(f"subjack error: {e}")
        else:
            out.caution("subjack not installed. Install it for subdomain takeover detection:")
            print(f"    go install github.com/haccer/subjack@latest")
            print(f"    Then run: subjack -w {domains_path} -t 20 -ssl -a")
