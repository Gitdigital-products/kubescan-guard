# KubeScan Guard

**Container & Kubernetes Security Auditor**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

KubeScan Guard scans Dockerfiles, Kubernetes manifests, and container images for security misconfigurations. It checks against CIS Docker/Kubernetes benchmarks and provides actionable remediation guidance.

## Install
```bash
pip install kubescan-guard
```

## Commands
| Command | Description |
|---------|-------------|
| `kubescan audit` | Full container security audit |
| `kubescan dockerfile` | Scan Dockerfile for issues |
| `kubescan k8s` | Scan K8s manifests |
| `kubescan images` | Check image security |
| `kubescan compliance` | CIS benchmark checks |
| `kubescan sbom` | Generate container SBOM |

## Quick Start
```bash
kubescan audit ./my-project
kubescan dockerfile ./Dockerfile
kubescan compliance ./k8s-manifests
```
