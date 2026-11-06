from phantomstalker.security.audit import System, audit
from phantomstalker.security.report import Severity


def make(os_name, commands, files=None):
    def run(cmd):
        return commands.get(tuple(cmd))

    return System(os_name, run=run, read=lambda p: (files or {}).get(p))


def titles(report, severity=None):
    return [f.title for f in report.findings if severity is None or f.severity == severity]


def test_linux_hardened_machine_scores_100():
    s = make("linux", {
        ("ufw", "status"): (0, "Status: active"),
        ("lsblk", "-o", "TYPE", "-n"): (0, "disk\npart\ncrypt\nlvm"),
        ("apt", "list", "--upgradable"): (0, "Listing... Done\n"),
        ("ss", "-tulnpH"): (0, 'tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=1,fd=5))'),
    }, {"/etc/ssh/sshd_config": "PermitRootLogin no\nPasswordAuthentication no\n"})
    r = audit(s)
    assert r.score == 100 and not r.issues
    assert any("ufw" in t for t in titles(r, Severity.OK))


def test_linux_insecure_machine_reports_problems():
    s = make("linux", {
        ("ufw", "status"): (0, "Status: inactive"),
        ("firewall-cmd", "--state"): None,
        ("lsblk", "-o", "TYPE", "-n"): (0, "disk\npart"),
        ("apt", "list", "--upgradable"): (0, "Listing...\nopenssl/jammy-security 3.0 amd64 [upgradable from: 2.9]\nvim/jammy 9 amd64 [upgradable from: 8]"),
        ("ss", "-tulnpH"): (0, 'tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=9,fd=6))\n'
                                'tcp LISTEN 0 511 0.0.0.0:8443 0.0.0.0:*'),
    }, {"/etc/ssh/sshd_config": "PermitRootLogin yes\n",
        "/etc/gdm3/custom.conf": "[daemon]\nAutomaticLoginEnable=true\n"})
    r = audit(s)
    high = titles(r, Severity.HIGH)
    assert any("Фаєрвол вимкнено" in t for t in high)
    assert any("Шифрування" in t for t in high)
    assert any("Безпекових оновлень" in t for t in high)
    assert any("6379" in t and "Redis" in t and "redis-server" in t for t in high)
    assert any("root" in t for t in high)
    assert any("8443" in t for t in titles(r, Severity.LOW))
    assert any("автоматичний вхід" in t for t in titles(r, Severity.MEDIUM))
    assert any("за паролем" in t for t in titles(r, Severity.MEDIUM))  # дефолт — yes
    assert r.score < 30


def test_ufw_needs_root_is_not_reported_as_disabled():
    s = make("linux", {("ufw", "status"): (1, "ERROR: You need to be root to run this script")})
    r = audit(s)
    assert any("root" in f.title for f in r.findings if f.severity == Severity.INFO)
    assert not any("Фаєрвол вимкнено" in t for t in titles(r))


def test_macos_checks():
    s = make("darwin", {
        ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"): (0, "Firewall is disabled. (State = 0)"),
        ("fdesetup", "status"): (0, "FileVault is On."),
        ("lsof", "-nP", "-iTCP", "-sTCP:LISTEN"): (0, "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
                                                     "ControlCe 1 me 9u IPv4 0x1 0t0 TCP *:5000 (LISTEN)"),
        ("csrutil", "status"): (0, "System Integrity Protection status: enabled."),
        ("spctl", "--status"): (0, "assessments disabled"),
    })
    r = audit(s)
    assert any("Фаєрвол вимкнено" in t for t in titles(r, Severity.HIGH))
    assert any("FileVault" in t for t in titles(r, Severity.OK))
    assert any("5000" in t for t in titles(r, Severity.HIGH))
    assert any("Gatekeeper" in t for t in titles(r, Severity.MEDIUM))


def test_windows_firewall_off():
    s = make("windows", {("netsh", "advfirewall", "show", "allprofiles", "state"): (0, "Domain Profile\nState ON\nPublic Profile\nState OFF")})
    r = audit(s)
    assert any("Фаєрвол" in t for t in titles(r, Severity.HIGH))


def test_broken_check_does_not_crash(monkeypatch):
    def boom(cmd):
        raise RuntimeError("x")

    r = audit(System("linux", run=boom, read=lambda p: None))
    assert any("помилка перевірки" in f.title for f in r.findings)
