import pytest
from pathlib import Path
@pytest.fixture
def dockerfile_project(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\nRUN apt-get update\nUSER root\nADD https://example.com/script.sh /\nENV DB_PASSWORD=secret123\nEXPOSE 22\nEXPOSE 2375\nRUN chmod 777 /app\nCOPY . .\n")
    return tmp_path
@pytest.fixture
def k8s_project(tmp_path):
    (tmp_path / "deploy.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        securityContext:\n          privileged: true\n          runAsUser: 0\n      hostNetwork: true\n      hostPID: true\n")
    return tmp_path
@pytest.fixture
def clean_project(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nRUN groupadd -r app && useradd -r -g app app\nUSER app\nCOPY --chown=app:app . /app\nHEALTHCHECK CMD curl -f http://localhost:8080/health\n")
    return tmp_path
