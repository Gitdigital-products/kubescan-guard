"""Dockerfile security scanner."""
import re
from pathlib import Path

INSECURE_PATTERNS = [
    (re.compile(r"FROM\s+\S+:latest", re.I), "critical", "Using :latest tag is unpredictable", "Pin to a specific version digest"),
    (re.compile(r"FROM\s+\S+@\s*sha256:"), "info", "Good: Using digest pinning", ""),
    (re.compile(r"USER\s+root", re.I), "high", "Running as root", "Use a non-root user"),
    (re.compile(r"^\s*#\s*USER", re.I), "medium", "USER instruction commented out", "Enable non-root user"),
    (re.compile(r"ADD\s+https?://", re.I), "high", "ADD downloads remote files (use COPY instead)", "Use COPY with multi-stage builds"),
    (re.compile(r"chmod\s+777", re.I), "critical", "World-writable permissions (777)", "Use最小权限: chmod 755 or less"),
    (re.compile(r"EXPOSE\s+22", re.I), "high", "SSH exposed (port 22)", "Remove SSH, use kubectl exec or docker exec"),
    (re.compile(r"EXPOSE\s+2375", re.I), "critical", "Docker daemon exposed (port 2375)", "Never expose Docker daemon"),
    (re.compile(r"ENV\s+\S*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+", re.I), "critical", "Secret hardcoded in ENV", "Use Docker secrets, mounted files, or runtime env"),
    (re.compile(r"HEALTHCHECK\s+.*--insecure", re.I), "high", "Insecure healthcheck", "Use HTTPS for health endpoints"),
    (re.compile(r"COPY\s+\.\s+\. "), "medium", "COPY . . copies everything", "Use .dockerignore to exclude sensitive files"),
    (re.compile(r"FROM\s+scratch", re.I), "info", "Using scratch (minimal image)", ""),
]

class DockerfileScanner:
    def scan(self, path: Path) -> dict:
        findings = []
        if path.is_file():
            findings.extend(self._scan_file(path))
        elif path.is_dir():
            for f in path.rglob("Dockerfile*"):
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
        for i, line in enumerate(content.split("\n"), 1):
            for pattern, severity, message, rec in INSECURE_PATTERNS:
                if pattern.search(line) and severity != "info":
                    findings.append({"severity": severity, "message": f"{message} ({path.name}:{i})", "file_path": str(path), "line": i, "rule_id": f"DOCKERFILE-{severity.upper()}", "recommendation": rec})
        return findings
