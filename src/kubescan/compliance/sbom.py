"""Container SBOM generation."""
from pathlib import Path
import json
from datetime import datetime, timezone

class ContainerSBOM:
    def generate(self, path: Path) -> dict:
        components = []
        for f in path.rglob("Dockerfile*"):
            content = f.read_text(errors="ignore")
            for line in content.split("\n"):
                line = line.strip()
                if line.upper().startswith("FROM "):
                    image = line.split()[1].split("@")[0]
                    components.append({"type": "container-image", "name": image, "source": str(f)})
        for f in path.rglob("package.json"):
            try:
                pkg = json.loads(f.read_text())
                for name, ver in pkg.get("dependencies", {}).items():
                    components.append({"type": "npm", "name": name, "version": ver.lstrip("^~>=< ")})
            except Exception:
                pass
        return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "tools": [{"name": "kubescan-guard", "version": "0.1.0"}]}, "components": components}
