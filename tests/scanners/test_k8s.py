from kubescan.scanners.k8s_scanner import K8sScanner
def test_detect_privileged(k8s_project):
    result = K8sScanner().scan(k8s_project / "deploy.yaml")
    assert any("privileged" in f["message"].lower() for f in result["findings"])
def test_detect_host_network(k8s_project):
    result = K8sScanner().scan(k8s_project / "deploy.yaml")
    assert any("host" in f["message"].lower() for f in result["findings"])
