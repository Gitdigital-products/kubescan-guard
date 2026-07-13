"""Kubernetes manifest security scanner."""
import re
from pathlib import Path

class K8sScanner:
    def scan(self, path: Path) -> dict:
        findings = []
        if path.is_file():
            findings.extend(self._scan_file(path))
        elif path.is_dir():
            for f in list(path.rglob("*.yaml")) + list(path.rglob("*.yml")):
                findings.extend(self._scan_file(f))
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        return {"findings": findings, "total": len(findings), "critical": critical, "high": high}

    def _scan_file(self, path: Path) -> list:
        findings = []
        try:
            content = path.read_text(errors="ignore")
        except (PermissionError, OSError):
            return findings
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if "privileged:\s*true" in s or "privileged: true" in s:
                findings.append({"severity": "critical", "message": f"Privileged container ({path.name}:{i})", "file_path": str(path), "line": i, "recommendation": "Remove privileged: true or use specific capabilities"})
            if "hostNetwork:\s*true" in s or "hostNetwork: true" in s:
                findings.append({"severity": "high", "message": f"Host network access ({path.name}:{i})", "file_path": str(path), "line": i, "recommendation": "Remove hostNetwork: true unless absolutely required"})
            if "hostPID:\s*true" in s or "hostPID: true" in s:
                findings.append({"severity": "high", "message": f"Host PID namespace ({path.name}:{i})", "file_path": str(path), "line": i, "recommendation": "Remove hostPID: true"})
            if "runAsUser:\s*0" in s or "runAsUser: 0" in s:
                findings.append({"severity": "high", "message": f"Running as root (UID 0) ({path.name}:{i})", "file_path": str(path), "line": i, "recommendation": "Use a non-root user"})
            if re.search(r"allowPrivilegeEscalation:\s*true", s):
                findings.append({"severity": "medium", "message": f"Privilege escalation allowed ({path.name}:{i})", "file_path": str(path), "line": i, "recommendation": "Set allowPrivilegeEscalation: false"})
            if "latest" in s and ("image:" in s or "image =" in s):
                findings.append({"severity": "medium", "message": f"Using :latest tag ({path.name}:{i})", "file_path": str(path), "line": i, "recommendation": "Pin to a specific version"})
        return findings
