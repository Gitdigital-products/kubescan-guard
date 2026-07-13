"""KubeScan Guard CLI."""
import sys, json, argparse
from pathlib import Path
from kubescan import __version__

def build_parser():
    p = argparse.ArgumentParser(prog="kubescan", description="KubeScan Guard - Container & K8s Security Auditor")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("audit", help="Audit Dockerfiles and K8s manifests").add_argument("path", nargs="?", default=".")
    sub.add_parser("dockerfile", help="Scan Dockerfile for security issues").add_argument("path", nargs="?", default="Dockerfile")
    sub.add_parser("k8s", help="Scan Kubernetes manifests").add_argument("path", nargs="?", default=".")
    sub.add_parser("images", help="Check container image security").add_argument("image")
    sub.add_parser("compliance", help="Check CIS benchmark compliance").add_argument("path", nargs="?", default=".")
    sub.add_parser("sbom", help="Generate container SBOM").add_argument("path", nargs="?", default=".")
    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help()
        return 0
    if args.command == "audit":
        from kubescan.core.auditor import ContainerAuditor
        result = ContainerAuditor().audit(Path(args.path))
        print(json.dumps(result, indent=2) if "--json" in (sys.argv or []) else _render(result))
        return 1 if result.get("critical", 0) > 0 else 0
    elif args.command == "dockerfile":
        from kubescan.scanners.dockerfile_scanner import DockerfileScanner
        result = DockerfileScanner().scan(Path(args.path))
        print(json.dumps(result, indent=2))
        return 1 if result.get("critical", 0) > 0 else 0
    elif args.command == "k8s":
        from kubescan.scanners.k8s_scanner import K8sScanner
        result = K8sScanner().scan(Path(args.path))
        print(json.dumps(result, indent=2))
        return 1 if result.get("critical", 0) > 0 else 0
    elif args.command == "images":
        from kubescan.scanners.image_scanner import ImageScanner
        result = ImageScanner().scan(args.image)
        print(json.dumps(result, indent=2))
        return 0
    elif args.command == "compliance":
        from kubescan.compliance.cis_benchmark import CISBenchmark
        result = CISBenchmark().check(Path(args.path))
        for c in result["checks"]:
            s = "PASS" if c["passed"] else "FAIL"
            print(f"  [{s}] {c['control']}: {c['detail']}")
        return 0 if result["passed"] else 1
    elif args.command == "sbom":
        from kubescan.compliance.sbom import ContainerSBOM
        sbom = ContainerSBOM().generate(Path(args.path))
        print(json.dumps(sbom, indent=2))
        return 0

def _render(result):
    lines = ["=" * 60, "  KubeScan Guard - Container Security Report", "=" * 60, ""]
    for f in result.get("findings", []):
        sym = "!!" if f["severity"] == "critical" else "! " if f["severity"] == "high" else "- "
        lines.append(f"  {sym}{f['severity'].upper():8s} {f['message']}")
    lines.append(f"\n  Total: {result.get('total', 0)}  Critical: {result.get('critical', 0)}  High: {result.get('high', 0)}")
    lines.append("=" * 60)
    return "\n".join(lines)

if __name__ == "__main__":
    sys.exit(main())
