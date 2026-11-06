"""/checkaddr та /approvals — безпека EVM-гаманців (Ethereum, Base, Arbitrum…).

Працює лише з публічними адресами. Сід-фраза чи приватний ключ не потрібні й ніколи не запитуються.
"""

from __future__ import annotations

import asyncio
import re

import httpx

from phantomstalker.security import net
from phantomstalker.security.report import Report, Severity, SecurityError

# --- Keccak-256 (як в Ethereum; відрізняється від SHA3-256 паддингом) ---------------------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(state)
    out = b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


# --- адреси ---------------------------------------------------------------------------------
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def to_checksum(address: str) -> str:
    hex_addr = address.lower().removeprefix("0x")
    digest = keccak256(hex_addr.encode()).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(hex_addr))


def checksum_status(address: str) -> str:
    """'valid' | 'invalid' | 'no-checksum' (усі літери одного регістру)."""
    body = address[2:]
    if body.lower() == body or body.upper() == body:
        return "no-checksum"
    return "valid" if to_checksum(address) == address else "invalid"


def poisoning(address: str, expected: str) -> bool:
    """Підозра на «отруєння адреси»: однакові початок і кінець, але різна середина."""
    a, b = address.lower(), expected.lower()
    return a != b and a[:6] == b[:6] and a[-4:] == b[-4:]


SCAM_LIST = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"


async def scam_addresses(client: httpx.AsyncClient) -> set[str]:
    cached = net.cache_get("scam_addresses", 24 * 3600)
    if cached is None:
        resp = await client.get(SCAM_LIST)
        resp.raise_for_status()
        cached = resp.json()
        net.cache_put("scam_addresses", cached)
    return {a.lower() for a in cached if isinstance(a, str)}


async def check_address(address: str, expected: str = "", client: httpx.AsyncClient | None = None) -> Report:
    address = address.strip()
    r = Report(f"Перевірка адреси · {address[:10]}…{address[-6:]}" if len(address) > 20 else "Перевірка адреси")
    if not ADDR_RE.match(address):
        if re.match(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$", address):
            raise SecurityError("Це Bitcoin-адреса — поки підтримуються лише EVM-адреси (0x…)")
        raise SecurityError("Потрібна EVM-адреса формату 0x + 40 hex-символів")
    status = checksum_status(address)
    if status == "invalid":
        r.add(Severity.HIGH, "Контрольна сума EIP-55 НЕ збігається",
              f"Правильний запис: {to_checksum(address)}", "Адресу пошкоджено або змінено — не надсилай кошти")
    elif status == "valid":
        r.add(Severity.OK, "Контрольна сума EIP-55 правильна")
    else:
        r.add(Severity.INFO, "Адреса без контрольної суми", f"З контрольною сумою: {to_checksum(address)}")
    if expected:
        expected = expected.strip()
        if address.lower() == expected.lower():
            r.add(Severity.OK, "Збігається з очікуваною адресою")
        elif poisoning(address, expected):
            r.add(Severity.CRITICAL, "Схоже на «отруєння адреси»!",
                  "Початок і кінець збігаються з очікуваною, але середина інша. Шахраї навмисно створюють такі адреси й "
                  "підкидають їх в історію транзакцій.", "Не надсилай! Скопіюй адресу з надійного джерела й звір повністю")
        else:
            r.add(Severity.HIGH, "НЕ збігається з очікуваною адресою", f"Очікувалась: {expected}")
    own = client is None
    client = client or net.client()
    try:
        scams = await scam_addresses(client)
    except (httpx.HTTPError, ValueError):
        r.add(Severity.INFO, "Список шахрайських адрес недоступний")
    else:
        if address.lower() in scams:
            r.add(Severity.CRITICAL, "Адреса в списку шахраїв (ScamSniffer)", "", "Не взаємодій з цією адресою")
        else:
            r.add(Severity.OK, f"Немає в списку шахраїв ScamSniffer ({len(scams):,} адрес)".replace(",", " "))
    finally:
        if own:
            await client.aclose()
    r.notes.append("Завжди звіряй адресу повністю, а не лише перші й останні символи.")
    return r


# --- дозволи токенів (approvals) -------------------------------------------------------------------
ETHERSCAN = "https://api.etherscan.io/v2/api"
APPROVAL_TOPIC = "0x" + keccak256(b"Approval(address,address,uint256)").hex()
CHAINS = {"eth": 1, "ethereum": 1, "base": 8453, "arbitrum": 42161, "arb": 42161, "optimism": 10,
          "op": 10, "polygon": 137, "bsc": 56, "bnb": 56, "linea": 59144}
KNOWN_SPENDERS = {
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router 2",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch v5",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch v6",
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "OpenSea Seaport",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
}
UNLIMITED = 2 ** 255


def _topic_address(topic: str) -> str:
    return "0x" + topic[-40:].lower()


def _decode_string(hex_data: str) -> str:
    data = bytes.fromhex(hex_data.removeprefix("0x"))
    try:
        if len(data) >= 64:
            length = int.from_bytes(data[32:64], "big")
            return data[64:64 + length].decode(errors="replace")
        return data.rstrip(b"\0").decode(errors="replace")
    except (ValueError, OverflowError):
        return ""


async def _etherscan(client: httpx.AsyncClient, chain: int, key: str, **params: str) -> object:
    resp = await client.get(ETHERSCAN, params={"chainid": chain, "apikey": key, **params})
    resp.raise_for_status()
    data = resp.json()
    if "result" not in data:
        raise SecurityError(f"Etherscan: {data.get('message', 'невідома помилка')}")
    if data.get("status") == "0" and data.get("message") not in ("No records found", "OK"):
        raise SecurityError(f"Etherscan: {data.get('result') or data.get('message')}")
    return data["result"]


async def approvals(owner: str, api_key: str, chain_name: str = "eth",
                    client: httpx.AsyncClient | None = None, delay: float = 0.25) -> Report:
    owner = owner.strip()
    if not ADDR_RE.match(owner):
        raise SecurityError("Потрібна адреса гаманця 0x…")
    chain = CHAINS.get(chain_name.lower())
    if chain is None:
        raise SecurityError("Мережі: " + ", ".join(sorted(set(CHAINS))))
    own = client is None
    client = client or net.client()
    try:
        logs = await _etherscan(client, chain, api_key, module="logs", action="getLogs", fromBlock="0",
                                toBlock="latest", topic0=APPROVAL_TOPIC, topic0_1_opr="and",
                                topic1="0x" + "0" * 24 + owner[2:].lower(), page="1", offset="1000")
        latest: dict[tuple[str, str], tuple[int, int, int]] = {}
        for log in logs if isinstance(logs, list) else []:
            topics = log.get("topics", [])
            if len(topics) != 3:  # NFT-approval має 4 топіки — тут лише ERC-20
                continue
            key = (log["address"].lower(), _topic_address(topics[2]))
            order = (int(log.get("blockNumber", "0x0"), 16), int(log.get("logIndex", "0x0") or "0x0", 16))
            amount = int(log.get("data", "0x0") or "0x0", 16)
            if key not in latest or order > latest[key][:2]:
                latest[key] = (*order, amount)
        active = [(tok, sp, amt) for (tok, sp), (_b, _i, amt) in latest.items() if amt > 0]
        scams: set[str] = set()
        try:
            scams = await scam_addresses(client)
        except (httpx.HTTPError, ValueError):
            pass
        r = Report(f"Дозволи токенів · {owner[:8]}…{owner[-4:]} · {chain_name}")
        checked = 0
        for token, spender, amount in sorted(active, key=lambda x: -x[2])[:25]:
            await asyncio.sleep(delay)
            try:  # поточний allowance — події могли застаріти
                current = await _etherscan(client, chain, api_key, module="proxy", action="eth_call", to=token,
                                           data="0xdd62ed3e" + owner[2:].lower().rjust(64, "0") + spender[2:].rjust(64, "0"),
                                           tag="latest")
                amount = int(str(current), 16) if str(current).startswith("0x") and len(str(current)) > 2 else amount
                await asyncio.sleep(delay)
                symbol = _decode_string(str(await _etherscan(client, chain, api_key, module="proxy",
                                                              action="eth_call", to=token, data="0x95d89b41", tag="latest")))
            except (SecurityError, ValueError, httpx.HTTPError):
                symbol = ""
            checked += 1
            if amount == 0:
                continue
            label = KNOWN_SPENDERS.get(spender)
            name = symbol or f"{token[:8]}…"
            who = label or f"{spender[:10]}…{spender[-4:]}"
            unlimited = amount >= UNLIMITED
            if spender in scams:
                sev, why = Severity.CRITICAL, "отримувач у списку шахраїв!"
            elif unlimited and not label:
                sev, why = Severity.HIGH, "необмежений доступ невідомому контракту"
            elif unlimited:
                sev, why = Severity.MEDIUM, "необмежений доступ (відомий протокол)"
            else:
                sev, why = Severity.LOW, f"ліміт {amount}"
            r.add(sev, f"{name} → {who}", f"{why} · токен {token} · отримувач {spender}",
                  f"Відклич на revoke.cash або https://etherscan.io/tokenapprovalchecker" if sev >= Severity.MEDIUM else "")
        if not r.findings:
            r.add(Severity.OK, "Активних дозволів ERC-20 не знайдено")
        r.summary = f"Подій Approval: {len(logs) if isinstance(logs, list) else 0} · активних дозволів: {len(active)}"
        r.notes.append("Показано ERC-20 дозволи (до 25 найбільших). NFT-дозволи (ApprovalForAll) перевір на revoke.cash.")
        return r
    except httpx.HTTPError as exc:
        raise SecurityError(net.describe_http_error(exc, "Etherscan")) from exc
    finally:
        if own:
            await client.aclose()
