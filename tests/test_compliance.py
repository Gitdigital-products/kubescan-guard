from pathlib import Path
from kubescan.compliance.cis_benchmark import CISBenchmark
def test_cis_checks(dockerfile_project):
    result = CISBenchmark().check(dockerfile_project)
    assert result["total"] > 0
