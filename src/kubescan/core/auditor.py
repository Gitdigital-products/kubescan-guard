from pathlib import Path
from kubescan.scanners.dockerfile_scanner import DockerfileScanner
from kubescan.scanners.k8s_scanner import K8sScanner
class ContainerAuditor:
    def audit(self, path: Path) -> dict:
        findings = []
        for f in path.rglob("Dockerfile*"):
            findings.extend(DockerfileScanner()._scan_file(f))
        for f in list(path.rglob("*.yaml")) + list(path.rglob("*.yml")):
            findings.extend(K8sScanner()._scan_file(f))
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        return {"findings": findings, "total": len(findings), "critical": critical, "high": high}
