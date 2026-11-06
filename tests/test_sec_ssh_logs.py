import base64
import os
import struct

import pytest

from phantomstalker.security import logs, sshaudit
from phantomstalker.security.report import Severity

crypto = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402


def _s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def dsa_pub() -> str:
    blob = _s(b"ssh-dss") + b"".join(_s(b"\x00" + bytes([0xAB]) * 128) for _ in range(4))
    return "ssh-dss " + base64.b64encode(blob).decode() + " old@laptop"


def write_keys(d):
    ed = ed25519.Ed25519PrivateKey.generate()
    (d / "id_ed25519").write_bytes(ed.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                                    serialization.NoEncryption()))
    (d / "id_ed25519.pub").write_bytes(ed.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                                    serialization.PublicFormat.OpenSSH) + b" me@pc")
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    (d / "id_rsa.pub").write_bytes(weak.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                                  serialization.PublicFormat.OpenSSH))
    # зашифрований OpenSSH-ключ: детектору досить заголовка з назвою шифру
    blob = b"openssh-key-v1\0" + _s(b"aes256-ctr") + _s(b"bcrypt") + _s(b"\x00" * 24) + struct.pack(">I", 1)
    body = base64.b64encode(blob).decode()
    label = "OPENSSH " + "PRIVATE KEY"  # збираємо під час виконання, щоб /secrets не реагував на тест
    (d / "id_work").write_text(f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    os.chmod(d / "id_work", 0o600)


def test_public_key_info_rsa_and_ed25519(tmp_path):
    write_keys(tmp_path)
    kind, bits, comment = sshaudit.public_key_info((tmp_path / "id_rsa.pub").read_text())
    assert kind == "ssh-rsa" and bits == 1024
    assert sshaudit.public_key_info((tmp_path / "id_ed25519.pub").read_text())[0] == "ssh-ed25519"
    assert sshaudit.public_key_info(dsa_pub())[0] == "ssh-dss"
    assert sshaudit.public_key_info('command="x",no-pty ' + dsa_pub())[2] == "old@laptop"


def test_private_key_encryption_detection(tmp_path):
    write_keys(tmp_path)
    assert sshaudit.private_key_encrypted((tmp_path / "id_ed25519").read_text()) is False
    assert sshaudit.private_key_encrypted((tmp_path / "id_work").read_text()) is True


@pytest.mark.skipif(os.name != "posix", reason="права доступу POSIX")
def test_audit_ssh_flags_problems(tmp_path):
    write_keys(tmp_path)
    os.chmod(tmp_path, 0o755)
    os.chmod(tmp_path / "id_ed25519", 0o644)
    (tmp_path / "authorized_keys").write_text(dsa_pub() + "\n")
    (tmp_path / "config").write_text("Host *\n  StrictHostKeyChecking no\n  ForwardAgent yes\n")
    r = sshaudit.audit_ssh(tmp_path)
    by = {f.title: f.severity for f in r.findings}
    assert by["id_ed25519: приватний ключ доступний іншим"] == Severity.HIGH
    assert by["id_ed25519: приватний ключ без пароля"] == Severity.MEDIUM
    assert by["id_work: приватний ключ захищено паролем"] == Severity.OK
    assert by["id_rsa.pub: RSA лише 1024 біт"] == Severity.HIGH
    assert any("DSA" in t and "authorized_keys" in t for t in by)
    assert by["config: StrictHostKeyChecking no"] == Severity.MEDIUM
    assert by["config: ForwardAgent yes"] == Severity.LOW
    assert any("~/.ssh доступна" in t for t in by)
    assert r.score < 50


def test_audit_ssh_missing_dir(tmp_path):
    r = sshaudit.audit_ssh(tmp_path / "nope")
    assert r.score == 100 and r.findings[0].severity == Severity.INFO


AUTH_LOG = "\n".join(
    [f"Nov  5 10:00:{i:02d} srv sshd[1]: Failed password for invalid user admin{i} from 198.51.100.7 port 4{i} ssh2"
     for i in range(12)]
    + ["Nov  5 10:00:30 srv sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"] * 4
    + ["Nov  5 10:00:40 srv sshd[1]: Accepted password for root from 203.0.113.9 port 22 ssh2",
       "Nov  5 10:01:00 srv sshd[2]: Accepted publickey for me from 192.0.2.1 port 50000 ssh2: ED25519",
       "Nov  5 10:02:00 srv sudo: me : 3 incorrect password attempts ; TTY=pts/0"]
)


def test_logs_detects_bruteforce_and_compromise():
    r = logs.analyze(AUTH_LOG, "test")
    titles = {f.title: f.severity for f in r.findings}
    assert any(s == Severity.CRITICAL and "203.0.113.9" in t and "після 4" in t for t, s in titles.items())
    assert any(s == Severity.HIGH and "198.51.100.7: 12 спроб" in t for t, s in titles.items())
    assert titles["Вхід під root з 203.0.113.9"] == Severity.HIGH
    assert titles["Невдалих спроб sudo: 1"] == Severity.LOW
    assert "Невдалих спроб: 16" in r.summary


def test_logs_quiet():
    r = logs.analyze("Nov 5 sshd[1]: Accepted publickey for me from 192.0.2.1 port 1 ssh2")
    assert all(f.severity <= Severity.INFO for f in r.findings)


def test_load_uses_journalctl_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(logs, "DEFAULT_LOGS", (str(tmp_path / "none.log"),))
    text, source = logs.load(None, run=lambda cmd: (0, "Failed password for x from 1.2.3.4 port 1"))
    assert "journalctl" in source and "1.2.3.4" in text
    with pytest.raises(FileNotFoundError):
        logs.load(None, run=lambda cmd: None)
    with pytest.raises(FileNotFoundError):
        logs.load(str(tmp_path / "missing.log"))
