import os


OUTPUT_DIR = "collected_code"


class BaseCollector:
    """Base class for AWS service collectors."""

    service_name = "unknown"

    def __init__(self, session):
        self.session = session
        self.output_dir = os.path.join(OUTPUT_DIR, self.service_name)
        os.makedirs(self.output_dir, exist_ok=True)

    def collect(self):
        """Yield (name, path) tuples of extracted code/config to scan."""
        raise NotImplementedError

    def write_file(self, name, content, ext="txt"):
        """Write content into a per-resource subdirectory. Returns the directory path."""
        resource_dir = os.path.join(self.output_dir, name)
        os.makedirs(resource_dir, exist_ok=True)
        path = os.path.join(resource_dir, f"{name}.{ext}")
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)
        return resource_dir
