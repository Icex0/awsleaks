from awsleaks import output as out


class BaseCheck:
    """Base class for surface exposure checks."""

    name = "unknown"

    def __init__(self, session):
        self.session = session
        self.findings = []

    def run(self):
        """Run the check. Populates self.findings."""
        raise NotImplementedError

    def add_finding(self, resource, detail, severity="HIGH", target=None, ports=None):
        """Add a finding. Optionally include target (IP/hostname) and ports for nmap output."""
        finding = {
            "check": self.name,
            "resource": resource,
            "detail": detail,
            "severity": severity,
            "target": target,
            "ports": ports or [],
        }
        self.findings.append(finding)

    def print_findings(self):
        if not self.findings:
            out.none("No exposed resources found")
            return

        for f in self.findings:
            out.warn(f['resource'])
            out.detail(f['detail'])
