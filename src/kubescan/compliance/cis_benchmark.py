"""CIS Docker/Kubernetes Benchmark checks."""
from pathlib import Path
import re

class CISBenchmark:
    def check(self, path: Path) -> dict:
        checks = []
        for f in path.rglob("Dockerfile*"):
            content = f.read_text(errors="ignore")
            lines = content.split("\n")
            has_user = any(re.match(r"^\s*USER\s+(?!root)", l, re.I) for l in lines)
            checks.append({"control": "CIS 4.1", "name": "Run as non-root user", "passed": has_user, "detail": "USER directive to non-root found" if has_user else "No non-root USER directive"})
            has_healthcheck = any("HEALTHCHECK" in l.upper() for l in lines)
            checks.append({"control": "CIS 4.6", "name": "HEALTHCHECK instruction", "passed": has_healthcheck, "detail": "HEALTHCHECK found" if has_healthcheck else "No HEALTHCHECK instruction"})
            no_latest = not any(re.match(r"FROM\s+\S+:latest", l, re.I) for l in lines if l.strip())
            checks.append({"control": "CIS 4.1", "name": "No :latest tag", "passed": no_latest, "detail": "No :latest tags" if no_latest else "Found :latest tag"})
            no_add_remote = not any(re.match(r"ADD\s+https?://", l, re.I) for l in lines)
            checks.append({"control": "CIS 4.2", "name": "No ADD with remote URL", "passed": no_add_remote, "detail": "No remote ADD" if no_add_remote else "Found ADD with remote URL"})
        passed = all(c["passed"] for c in checks) if checks else True
        return {"checks": checks, "passed": passed, "total": len(checks), "passed_count": sum(1 for c in checks if c["passed"])}
