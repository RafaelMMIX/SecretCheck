from pathlib import Path

from secretcheck.scanner import scan_line, scan_file, scan_directory


def test_detects_api_key():
    result = scan_line('api_key = "FAKE_API_KEY_123"')

    assert "api_key" in result

def test_detects_password():
    result = scan_line('password = "FAKE_PASSWORD_123"')
    assert "password" in result


def test_detects_token():
    result = scan_line('access_token = "FAKE_TOKEN_123"')
    assert "token" in result


def test_ignores_environment_variable():
    result = scan_line('password = os.getenv("PASSWORD")')
    assert result == []

def test_scan_file(tmp_path):
    file_path = tmp_path / "config.py"
    file_path.write_text(
        'api_key = "FAKE_API_KEY_123"\n'
        'password = "FAKE_PASSWORD_123"\n',
        encoding="utf-8",
    )

    results = scan_file(file_path)

    assert len(results) == 2
    assert results[0]["line"] == 1
    assert results[0]["type"] == "api_key"
    assert results[1]["line"] == 2
    assert results[1]["type"] == "password"


def test_scan_directory(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    (project / "app.py").write_text(
        'token = "FAKE_TOKEN_123"\n',
        encoding="utf-8",
    )

    results = scan_directory(project)

    assert len(results) == 1
    assert results[0]["type"] == "token"

def test_scan_file_missing_file(tmp_path):
    file_path = tmp_path / "missing.py"

    results = scan_file(file_path)

    assert results == []

def test_scan_file_invalid_encoding(tmp_path):
    file_path = tmp_path / "invalid.py"
    file_path.write_bytes(b"\xff\xfe\xfa")

    results = scan_file(file_path)

    assert results == []

def test_scan_directory_ignores_git(tmp_path):
    project = tmp_path / "project"
    git_dir = project / ".git"

    git_dir.mkdir(parents=True)

    (git_dir / "config.py").write_text(
        'api_key = "FAKE_API_KEY_123"\n',
        encoding="utf-8",
    )

    (project / "app.py").write_text(
        'password = "FAKE_PASSWORD_123"\n',
        encoding="utf-8",
    )

    results = scan_directory(project)

    assert len(results) == 1
    assert results[0]["type"] == "password"