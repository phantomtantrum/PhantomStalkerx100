"""/breach — чи світилася ТВОЯ пошта у витоках (Have I Been Pwned, потрібен платний ключ).

Перевіряються лише власні адреси — застосунок просить підтвердження перед кожною перевіркою.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import quote

import httpx

from phantomstalker.security import net
from phantomstalker.security.report import Report, Severity, SecurityError

HIBP = "https://haveibeenpwned.com/api/v3/breachedaccount/"
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SENSITIVE = {"Passwords", "Password hints", "Security questions and answers", "Credit cards",
             "Bank account numbers", "Partial credit card data", "Government issued IDs",
             "Passport numbers", "Auth tokens", "Private messages", "Crypto wallet hashes"}


def valid_email(value: str) -> bool:
    return bool(EMAIL.match(value.strip()))


def value_hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


async def check(email: str, api_key: str, client: httpx.AsyncClient | None = None) -> Report:
    email = email.strip()
    if not valid_email(email):
        raise SecurityError("Це не схоже на адресу пошти")
    own = client is None
    client = client or net.client()
    try:
        resp = await client.get(HIBP + quote(email), params={"truncateResponse": "false"},
                                headers={"hibp-api-key": api_key})
        if resp.status_code == 404:
            breaches = []
        else:
            resp.raise_for_status()
            breaches = resp.json()
    except httpx.HTTPError as exc:
        raise SecurityError(net.describe_http_error(exc, "Have I Been Pwned")) from exc
    finally:
        if own:
            await client.aclose()

    r = Report(f"Витоки даних · {email}")
    if not breaches:
        r.add(Severity.OK, "Адресу не знайдено у відомих витоках")
        r.summary = "Чудово — але все одно використовуй унікальні паролі й 2FA"
        return r
    breaches.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)
    for b in breaches:
        classes = b.get("DataClasses", [])
        bad = SENSITIVE & set(classes)
        sev = Severity.HIGH if "Passwords" in classes else Severity.MEDIUM if bad else Severity.LOW
        r.add(sev, f"{b.get('Title', b.get('Name'))} · {b.get('BreachDate', '')}",
              "Витекло: " + ", ".join(classes[:8]),
              "Зміни пароль на цьому сайті та всюди, де він повторювався; увімкни 2FA" if "Passwords" in classes else "")
    with_pw = sum(1 for b in breaches if "Passwords" in b.get("DataClasses", []))
    r.summary = f"Витоків: {len(breaches)} · з паролями: {with_pw}"
    r.notes.append("Дані: haveibeenpwned.com. Адреса зберігається локально лише у вигляді хешу.")
    return r
