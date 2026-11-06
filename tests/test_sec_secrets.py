import subprocess

import pytest

from phantomstalker.security import secrets_scan
from phantomstalker.security.report import Severity
from tests.conftest import fake


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(root)})


def test_mask_never_reveals_full_value():
    token = fake("gh" + "p_", 36)
    assert secrets_scan.mask(token) == token[:4] + "…" + token[-4:]
    assert token not in secrets_scan.mask(token)


def test_scan_text_rules():
    gh = fake("gh" + "p_", 36)
    aws = "AK" + "IA" + "Q3XK9ABCDE7FGH2J"
    pk = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    text = f'token = "{gh}"\nkey={aws}\n{pk}\npassword = "hunter2hunter2"\npassword = "your_password_here"'
    hits = secrets_scan.scan_text(text, "app.py")
    names = {h.rule.name for h in hits}
    assert {"GitHub токен", "AWS Access Key", "Приватний ключ", "Пароль у коді"} <= names
    assert all(gh not in h.masked for h in hits)
    assert sum(h.rule.name == "Пароль у коді" for h in hits) == 1  # плейсхолдер пропущено


def test_scan_tree_skips_vendor_and_binary(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("k = '" + fake("sk-ant-", 30) + "'")
    (tmp_path / "blob.bin").write_bytes(b"\0" + fake("gh" + "p_", 36).encode())
    (tmp_path / "ok.py").write_text("print('hi')")
    r = secrets_scan.scan(tmp_path)
    assert r.findings[0].severity == Severity.OK


@pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode != 0, reason="немає git")
def test_history_and_tracked_env(tmp_path):
    git(tmp_path, "init", "-q")
    key = fake("sk-ant-api03-", 40)
    (tmp_path / "config.py").write_text(f"API_KEY = '{key}'\n")
    (tmp_path / ".env").write_text("DB_PASS=x\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "oops")
    (tmp_path / "config.py").write_text("import os\nAPI_KEY = os.environ['API_KEY']\n")
    git(tmp_path, "commit", "-qam", "fix")
    r = secrets_scan.scan(tmp_path)
    titles = [f.title for f in r.findings]
    assert any("в історії git" in t and "Anthropic" in t for t in titles)
    assert any(".env закомічено" in t for t in titles)
    assert all(key not in f.title + f.detail for f in r.findings)
    assert "історію git перевірено" in r.summary


def test_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        secrets_scan.scan(tmp_path / "nope")
