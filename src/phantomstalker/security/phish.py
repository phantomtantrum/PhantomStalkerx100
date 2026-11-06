"""/phish — аналіз підозрілих листів, повідомлень і посилань. Посилання НЕ відкриваються."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html import unescape
from urllib.parse import urlsplit

from phantomstalker.security.report import Report, Severity

BRANDS = {
    "paypal", "google", "gmail", "apple", "icloud", "microsoft", "outlook", "office", "amazon",
    "facebook", "instagram", "whatsapp", "telegram", "netflix", "binance", "coinbase", "kraken",
    "metamask", "trustwallet", "ledger", "trezor", "phantom", "uniswap", "opensea", "github",
    "privatbank", "privat24", "monobank", "oschadbank", "diia", "novaposhta", "ukrposhta", "olx",
    "steam", "discord", "linkedin", "dropbox", "docusign", "dhl", "fedex", "booking",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
              "buff.ly", "tiny.cc", "shorturl.at", "t.ly", "rebrand.ly", "s.id"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga",
              "work", "support", "rest", "fit", "cam", "icu", "buzz", "monster"}
URGENT = re.compile(
    r"терміново|негайно|протягом 24|заблоков|блокуванн|підтвердіть|верифікац|ваш акаунт|"
    r"виграли|приз|компенсаці|виплат|срочно|заблокирован|подтвердите|"
    r"urgent|immediately|suspended|verify your|confirm your|password expire|unusual activity|"
    r"gift card|airdrop|claim (?:your|now)|wallet ?connect|limited time", re.I)
SEED = re.compile(r"seed|сід|мнемонічн|мнемоническ|recovery phrase|secret phrase|"
                  r"приватн\w* ключ|private key|12 слів|24 слів|12 words|24 words", re.I)
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|ua|ru|xyz|top|app|me|co|info|site|online|link|click|zip|mov)\b", re.I)
AUTH = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)
SECOND_LEVEL = {"co.uk", "com.ua", "org.ua", "net.ua", "in.ua", "kiev.ua", "com.au", "co.jp", "com.br"}


def registrable(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _distance(a: str, b: str) -> int:
    """Відстань Дамерау–Левенштейна (обмежена)."""
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "4": "a", "7": "t"})


def _scripts(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0])
    return out


def analyze_url(url: str) -> list[tuple[Severity, str]]:
    flags: list[tuple[Severity, str]] = []
    had_scheme = bool(re.match(r"https?://", url, re.I))
    if not had_scheme:
        url = "http://" + url
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return flags
    if "@" in parts.netloc:
        flags.append((Severity.HIGH, "у посиланні є «@» — справжня адреса прихована після нього"))
    try:
        ipaddress.ip_address(host)
        flags.append((Severity.HIGH, "замість домену — IP-адреса"))
        return flags
    except ValueError:
        pass
    shown = host
    if "xn--" in host:
        try:
            shown = host.encode().decode("idna")
        except UnicodeError:
            pass
        flags.append((Severity.HIGH, f"punycode-домен: виглядає як «{shown}»"))
    scripts = _scripts(shown)
    if len(scripts) > 1:
        flags.append((Severity.HIGH, f"у домені змішано алфавіти ({', '.join(sorted(scripts))}) — підміна літер"))
    reg = registrable(shown)
    base = reg.split(".")[0]
    normalized = base.translate(_CONFUSABLE).replace("-", "")
    tokens = [t.translate(_CONFUSABLE) for t in re.split(r"[-_]", base) if t]
    for brand in BRANDS:
        if base == brand:
            break
        lookalike = normalized == brand or any(
            t == brand or (len(brand) >= 5 and 0 < _distance(t, brand) <= (1 if len(brand) < 7 else 2))
            for t in [normalized, *tokens])
        if lookalike:
            flags.append((Severity.HIGH, f"домен {reg} схожий на {brand} — можливий двійник"))
            break
        if brand in shown.replace(reg, "") or (brand in base and base != brand):
            flags.append((Severity.HIGH, f"«{brand}» у назві, але справжній домен — {reg}"))
            break
    if reg in SHORTENERS:
        flags.append((Severity.MEDIUM, "скорочене посилання ховає справжню адресу"))
    tld = shown.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        flags.append((Severity.LOW, f"доменна зона .{tld} часто використовується шахраями"))
    if had_scheme and parts.scheme == "http":
        flags.append((Severity.LOW, "без HTTPS"))
    if shown.count(".") >= 4:
        flags.append((Severity.LOW, "дуже багато піддоменів"))
    if re.search(r"login|signin|verify|secure|account|wallet|update|confirm|auth", url, re.I) and flags:
        flags.append((Severity.LOW, "у посиланні слова на кшталт login/verify/wallet"))
    return flags


def _body_and_headers(raw: str) -> tuple[str, dict[str, str] | None]:
    looks_like_email = re.match(r"^(?:Received|Return-Path|From|Delivered-To|Message-ID|Subject):", raw.lstrip(), re.I | re.M)
    if not looks_like_email:
        return raw, None
    msg = Parser(policy=policy.default).parsestr(raw)
    headers = {k.lower(): str(v) for k, v in msg.items()}
    body_parts = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except (LookupError, ValueError):
                content = str(part.get_payload())
            if ctype == "text/html":
                urls = re.findall(r'href=["\']([^"\']+)', content, re.I)
                content = unescape(re.sub(r"<[^>]+>", " ", content)) + " " + " ".join(urls)
            body_parts.append(content)
    return "\n".join(body_parts) or str(msg.get_payload()), headers


def analyze(raw: str) -> Report:
    text, headers = _body_and_headers(raw)
    r = Report("Аналіз на фішинг")
    risk = 0

    def flag(sev: Severity, title: str, detail: str = "") -> None:
        nonlocal risk
        r.add(sev, title, detail)
        risk += {Severity.CRITICAL: 60, Severity.HIGH: 30, Severity.MEDIUM: 15, Severity.LOW: 5}.get(sev, 0)

    if headers is not None:
        auth = " ".join(v for k, v in headers.items() if k in ("authentication-results", "arc-authentication-results"))
        results = {k.lower(): v.lower() for k, v in AUTH.findall(auth)}
        for check in ("spf", "dkim", "dmarc"):
            value = results.get(check)
            if value in ("fail", "softfail", "permerror"):
                flag(Severity.HIGH, f"{check.upper()}: {value}", "Відправник не підтверджений поштовим сервером домену.")
            elif value == "pass":
                r.add(Severity.OK, f"{check.upper()}: pass")
            elif check == "dmarc" and results:
                flag(Severity.LOW, f"DMARC: {value or 'немає'}")
        from_name, from_addr = parseaddr(headers.get("from", ""))
        from_dom = from_addr.rsplit("@", 1)[-1].lower() if "@" in from_addr else ""
        reply_dom = parseaddr(headers.get("reply-to", ""))[1].rsplit("@", 1)[-1].lower()
        if reply_dom and from_dom and registrable(reply_dom) != registrable(from_dom):
            flag(Severity.MEDIUM, "Reply-To веде на інший домен", f"From: {from_dom} → Reply-To: {reply_dom}")
        ret_dom = parseaddr(headers.get("return-path", ""))[1].rsplit("@", 1)[-1].lower()
        if ret_dom and from_dom and registrable(ret_dom) != registrable(from_dom):
            flag(Severity.LOW, "Return-Path з іншого домену", f"{ret_dom}")
        name = from_name.casefold().replace(" ", "")
        sender_base = registrable(from_dom).split(".")[0] if from_dom else ""
        for brand in BRANDS:
            if brand in name and sender_base != brand:
                flag(Severity.HIGH, f"Відправник називає себе «{from_name}», але пише з {from_dom or 'невідомого домену'}")
                break
        if from_dom and (sender_flags := [m for sev, m in analyze_url(from_dom) if sev >= Severity.MEDIUM]):
            flag(Severity.HIGH, f"Підозрілий домен відправника: {from_dom}", "; ".join(sender_flags))
        if subject := headers.get("subject"):
            r.notes.append(f"Тема: {subject}")

    if SEED.search(text):
        flag(Severity.CRITICAL, "Просять сід-фразу або приватний ключ",
             "Жоден справжній сервіс ніколи цього не просить. Це 100% шахрайство.")
    urgent = sorted({m.group(0).lower() for m in URGENT.finditer(text)})
    if urgent:
        flag(Severity.MEDIUM, "Тиск і терміновість", "Фрази: " + ", ".join(urgent[:6]))

    found = URL_RE.findall(text)
    bare = [d for d in DOMAIN_RE.findall(text) if not any(d.lower() in u.lower() for u in found)]
    urls = list(dict.fromkeys(found + bare))
    for url in urls[:15]:
        url = url.rstrip(".,;:!?")
        flags = analyze_url(url)
        if flags:
            worst = max(s for s, _ in flags)
            flag(worst, f"Посилання: {url[:80]}", "; ".join(msg for _, msg in flags))
        else:
            r.add(Severity.INFO, f"Посилання: {url[:80]}", "явних ознак підробки не видно")

    bad_link = any(f.severity >= Severity.HIGH and f.title.startswith("Посилання") for f in r.findings)
    if bad_link and urgent:
        risk += 20  # тиск + підроблене посилання — класична схема фішингу
        r.notes.append("Поєднання тиску й підробленого посилання — класична схема фішингу.")
    risk = min(risk, 100)
    verdict = ("Ймовірно фішинг" if risk >= 60 else "Підозріло" if risk >= 30
               else "Явних ознак фішингу не знайдено")
    r.title = f"Аналіз на фішинг · {verdict} · ризик {risk}/100"
    r.summary = f"Посилань: {len(urls)}" + (" · заголовки листа перевірено" if headers is not None else "")
    r.notes.append("Посилання не відкривались — аналіз лише за текстом. Не переходь за підозрілими посиланнями.")
    if headers is None:
        r.notes.append("Для перевірки SPF/DKIM збережи лист як .eml і передай шлях: /phish лист.eml")
    return r
