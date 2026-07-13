from kubescan.scanners.dockerfile_scanner import DockerfileScanner
def test_detect_latest_tag(dockerfile_project):
    result = DockerfileScanner().scan(dockerfile_project / "Dockerfile")
    assert any("latest" in f["message"] for f in result["findings"])
def test_detect_root_user(dockerfile_project):
    result = DockerfileScanner().scan(dockerfile_project / "Dockerfile")
    assert any("root" in f["message"].lower() for f in result["findings"])
def test_detect_exposed_ports(dockerfile_project):
    result = DockerfileScanner().scan(dockerfile_project / "Dockerfile")
    assert any("22" in f["message"] or "2375" in f["message"] for f in result["findings"])
def test_detect_hardcoded_secret(dockerfile_project):
    result = DockerfileScanner().scan(dockerfile_project / "Dockerfile")
    assert any("secret" in f["message"].lower() or "password" in f["message"].lower() for f in result["findings"])
def test_clean_dockerfile(clean_project):
    result = DockerfileScanner().scan(clean_project / "Dockerfile")
    critical = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(critical) == 0
