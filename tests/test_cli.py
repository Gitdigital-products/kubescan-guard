from kubescan.__main__ import main, build_parser
def test_version(capsys):
    try: main(["--version"])
    except SystemExit: pass
    assert "kubescan" in capsys.readouterr().out.lower()
def test_no_command():
    assert main([]) == 0
