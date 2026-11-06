"""/pwned та /passgen — витоки паролів (k-анонімність), оцінка стійкості, генератор.

Пароль ніколи не надсилається: у Pwned Passwords іде лише 5 перших символів SHA-1 хешу,
а збіг шукається локально. Пароль не зберігається й не з'являється в стрічці.
"""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import string

import httpx

from phantomstalker.security import net
from phantomstalker.security.report import Report, Severity, SecurityError

RANGE_API = "https://api.pwnedpasswords.com/range/"

COMMON = """123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball
abc123 football monkey letmein 696969 shadow master 666666 qwertyuiop 123321 mustang 1234567890 michael
654321 superman 1qaz2wsx 7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm
asdfgh hunter buster soccer harley batman andrew tigger sunshine iloveyou 2000 charlie robert thomas
hockey ranger daniel starwars klaster 112233 george computer michelle jessica pepper 1111 zxcvbn 555555
11111111 131313 freedom 777777 pass maggie 159753 aaaaaa ginger princess joshua cheese amanda summer love
ashley nicole chelsea biteme matthew access yankees 987654321 dallas austin thunder taylor matrix admin
welcome login passw0rd password1 qwerty123 1q2w3e4r 1q2w3e qwe123 zaq12wsx йцукен пароль привіт
qwerty1 abc12345 secret changeme default root toor test guest""".split()

KEYBOARD = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "йцукенгшщзхї", "фівапролджє"]


def _charset(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^\w\s]|_", pw):
        size += 33
    if re.search(r"[^\x00-\x7f]", pw):
        size += 66
    if " " in pw:
        size += 1
    return max(size, 1)


def entropy(pw: str) -> float:
    """Приблизна ентропія в бітах з поправками на очевидні шаблони."""
    if not pw:
        return 0.0
    low = pw.lower()
    if low in COMMON or re.sub(r"\d+$", "", low) in COMMON:
        return math.log2(len(COMMON) * 100)
    bits = len(pw) * math.log2(_charset(pw))
    # повтори (aaaa, abcabc)
    if re.search(r"(.)\1{2,}", pw):
        bits *= 0.75
    if re.fullmatch(r"(.+?)\1+", pw):
        bits *= 0.5
    # клавіатурні та алфавітні послідовності
    for row in KEYBOARD + [string.ascii_lowercase]:
        for size in (4, 5, 6):
            if any(row[i:i + size] in low for i in range(len(row) - size + 1)):
                bits -= size * 2.5
                break
    if re.search(r"(19|20)\d\d", pw):
        bits -= 6
    if re.fullmatch(r"\d+", pw):
        bits = min(bits, len(pw) * math.log2(10))
    return max(bits, 1.0)


def crack_time(bits: float, guesses_per_second: float = 1e10) -> str:
    seconds = 2 ** bits / 2 / guesses_per_second
    for limit, unit in ((60, "с"), (3600, "хв"), (86400, "год"), (86400 * 365, "дн")):
        if seconds < limit:
            div = {"с": 1, "хв": 60, "год": 3600, "дн": 86400}[unit]
            return f"{max(seconds / div, 0):.0f} {unit}" if seconds >= 1 else "миттєво"
    years = seconds / (86400 * 365)
    if years > 1e9:
        return "мільярди років"
    if years > 1e6:
        return f"{years / 1e6:.0f} млн років"
    return f"{years:,.0f} років".replace(",", " ")


def rating(bits: float) -> tuple[Severity, str]:
    if bits < 28:
        return Severity.CRITICAL, "дуже слабкий"
    if bits < 40:
        return Severity.HIGH, "слабкий"
    if bits < 60:
        return Severity.MEDIUM, "середній"
    if bits < 80:
        return Severity.OK, "сильний"
    return Severity.OK, "дуже сильний"


async def pwned_count(password: str, client: httpx.AsyncClient) -> int:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    resp = await client.get(RANGE_API + prefix, headers={"Add-Padding": "true"})
    resp.raise_for_status()
    for line in resp.text.splitlines():
        h, _, count = line.strip().partition(":")
        if h == suffix:
            return int(count or 0)
    return 0


async def check(password: str, client: httpx.AsyncClient | None = None) -> Report:
    if not password:
        raise SecurityError("Порожній пароль")
    r = Report("Перевірка пароля")
    bits = entropy(password)
    sev, label = rating(bits)
    r.add(sev, f"Стійкість: {label} (~{bits:.0f} біт)",
          f"Довжина {len(password)} · офлайн-перебір: {crack_time(bits)}",
          "" if sev == Severity.OK else "Використай довшу фразу: /passgen")
    own = client is None
    client = client or net.client()
    try:
        count = await pwned_count(password, client)
    except httpx.HTTPError as exc:
        r.add(Severity.INFO, "База витоків недоступна", net.describe_http_error(exc, "Pwned Passwords"))
    else:
        if count:
            r.add(Severity.CRITICAL, f"Пароль знайдено у витоках: {count:,} разів".replace(",", " "),
                  "Його вже є в словниках зловмисників — він зламується за секунди.",
                  "Зміни його всюди, де використовував, і більше не використовуй")
        else:
            r.add(Severity.OK, "У відомих витоках не знайдено")
    finally:
        if own:
            await client.aclose()
    r.notes.append("Пароль не залишав твій комп'ютер: у сервіс пішли лише 5 символів його хешу.")
    return r


# --- генератор --------------------------------------------------------------------------
CONSONANTS = "bdfghjklmnprstvz"
VOWELS = "aeiou"


def generate_password(length: int = 20) -> str:
    length = max(12, min(length, 128))
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


def generate_passphrase(words: int = 6) -> tuple[str, float]:
    """Вимовні «слова» з 3 складів; ентропія рахується точно."""
    words = max(4, min(words, 12))
    syllables = [c + v for c in CONSONANTS for v in VOWELS]
    phrase = [ "".join(secrets.choice(syllables) for _ in range(3)) for _ in range(words)]
    digit_pos = secrets.randbelow(words)
    phrase[digit_pos] += str(secrets.randbelow(10))
    bits = words * 3 * math.log2(len(syllables)) + math.log2(words * 10)
    return "-".join(phrase), bits


def passgen_report(arg: str = "") -> Report:
    r = Report("Генератор паролів")
    n = int(arg) if arg.strip().isdigit() else 0
    pw = generate_password(n or 20)
    pw_bits = len(pw) * math.log2(75)
    phrase, ph_bits = generate_passphrase(6)
    r.add(Severity.OK, pw, f"Випадковий пароль · ~{pw_bits:.0f} біт · {crack_time(pw_bits)}")
    r.add(Severity.OK, phrase, f"Парольна фраза (легше запам'ятати) · ~{ph_bits:.0f} біт · {crack_time(ph_bits)}")
    r.notes.append("Збережи в менеджері паролів (Bitwarden, 1Password, KeePassXC). Генерація — локальна, криптостійким генератором.")
    return r
