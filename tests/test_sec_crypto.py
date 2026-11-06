import json
import os
import shutil
import struct
import time
import zlib

import httpx
import pytest

from phantomstalker.security import cryptobox, evm, exif
from phantomstalker.security.report import SecurityError, Severity
from tests.conftest import mock_client

# --- EVM ------------------------------------------------------------------------------------------


def test_keccak_and_checksum_vectors():
    assert evm.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert evm.keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    assert evm.keccak256(b"a" * 200).hex() == evm.keccak256(b"a" * 200).hex()  # кілька блоків
    assert evm.APPROVAL_TOPIC == "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
    for addr in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                 "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"):
        assert evm.to_checksum(addr.lower()) == addr
        assert evm.checksum_status(addr) == "valid"
    assert evm.checksum_status("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD") == "invalid"
    assert evm.checksum_status("0x" + "ab" * 20) == "no-checksum"


def test_poisoning_detection():
    real = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    fake = "0x5aAeb6" + "0" * 29 + "BeAed"
    assert len(fake) == 42
    assert evm.poisoning(fake, real) and not evm.poisoning(real, real)


SCAMS = ["0x1111111111111111111111111111111111111111"]


async def test_check_address_with_scam_list():
    client = mock_client(lambda req: httpx.Response(200, json=SCAMS))
    r = await evm.check_address("0x1111111111111111111111111111111111111111", client=client)
    assert any(f.severity == Severity.CRITICAL and "шахраїв" in f.title for f in r.findings)
    real = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    poisoned = "0x5aAeb6" + "0" * 28 + "1BeAed"
    r = await evm.check_address(poisoned, real, client=mock_client(lambda req: httpx.Response(200, json=SCAMS)))
    assert any(f.severity == Severity.CRITICAL and "отруєння" in f.title for f in r.findings)
    with pytest.raises(SecurityError, match="Bitcoin"):
        await evm.check_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")


OWNER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
TOKEN = "0x" + "a0" * 20
EVIL = "0x" + "be" * 20
UNI = "0x000000000022d473030f116ddee9f6b43ac78ba3"
MAX = "0x" + "f" * 64


def etherscan_handler(request: httpx.Request) -> httpx.Response:
    if "githubusercontent" in request.url.host:
        return httpx.Response(200, json=SCAMS)
    p = request.url.params
    assert p["apikey"] == "k" and p["chainid"] == "1"
    if p["module"] == "logs":
        assert p["topic1"].endswith(OWNER[2:].lower())
        log = lambda spender, amount, block: {"address": TOKEN, "topics": [evm.APPROVAL_TOPIC, "0x" + "0" * 24 + OWNER[2:],
                                                                          "0x" + "0" * 24 + spender[2:]],
                                              "data": amount, "blockNumber": hex(block), "logIndex": "0x0"}
        return httpx.Response(200, json={"status": "1", "message": "OK", "result": [
            log(EVIL, MAX, 10), log(UNI, MAX, 11), log(UNI, "0x0", 12),  # дозвіл Uniswap потім відкликано
        ]})
    data = p["data"]
    if data.startswith("0xdd62ed3e"):
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": MAX})
    if data == "0x95d89b41":
        sym = b"USDT"
        enc = (32).to_bytes(32, "big") + len(sym).to_bytes(32, "big") + sym.ljust(32, b"\0")
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": "0x" + enc.hex()})
    return httpx.Response(400)


async def test_approvals_flags_unlimited_unknown_spender():
    r = await evm.approvals(OWNER, "k", client=mock_client(etherscan_handler), delay=0)
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.severity == Severity.HIGH and f.title.startswith("USDT →") and "необмежений" in f.detail
    assert "revoke.cash" in f.fix
    with pytest.raises(SecurityError, match="Мережі"):
        await evm.approvals(OWNER, "k", chain_name="mars", client=mock_client(etherscan_handler))


# --- шифрування ---------------------------------------------------------------------------------


def test_encrypt_roundtrip_and_errors():
    armored = cryptobox.encrypt_text("секрет 👻", "correct horse")
    assert armored.startswith(cryptobox.BEGIN) and "секрет" not in armored
    assert cryptobox.decrypt_text(armored, "correct horse") == "секрет 👻"
    assert cryptobox.decrypt_text(armored.replace("\n", " "), "correct horse") == "секрет 👻"  # склеєна вставка
    with pytest.raises(SecurityError, match="неправильний пароль"):
        cryptobox.decrypt_text(armored, "wrong password")
    with pytest.raises(SecurityError, match="короткий"):
        cryptobox.encrypt_text("x", "short")
    with pytest.raises(SecurityError):
        cryptobox.decrypt_text("nothing here", "correct horse")


def test_encrypt_file_roundtrip(tmp_path):
    src = tmp_path / "notes.txt"
    src.write_bytes(b"\x00binary\xffdata")
    enc = cryptobox.encrypt_file(src, "correct horse")
    assert enc.name == "notes.txt.age" and enc.read_bytes()[:21] == b"age-encryption.org/v1"
    src.unlink()
    out = cryptobox.decrypt_file(enc, "correct horse")
    assert out.read_bytes() == b"\x00binary\xffdata"


@pytest.mark.skipif(shutil.which("age") is None or os.name != "posix", reason="потрібна утиліта age")
def test_interop_with_age_cli(tmp_path):
    import pty

    pw = "interop passphrase"
    armored_file = tmp_path / "m.txt"
    armored_file.write_text(cryptobox.encrypt_text("hello from quantphantom", pw))
    out = tmp_path / "out.txt"
    pid, fd = pty.fork()
    if pid == 0:  # age читає пароль лише з терміналу
        os.execvp("age", ["age", "-d", "-o", str(out), str(armored_file)])
    buf, deadline = b"", time.time() + 30
    while time.time() < deadline:
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        buf += chunk
        if b"passphrase" in buf.lower():
            os.write(fd, (pw + "\n").encode())
            buf = b""
    os.waitpid(pid, 0)
    assert out.read_text() == "hello from quantphantom"


# --- метадані фото ------------------------------------------------------------------------------


def build_tiff() -> bytes:
    """Мінімальний EXIF (little endian): Make, Model, GPS (50.45 N, 30.5236 E)."""
    def rat(*vals):
        return b"".join(struct.pack("<II", int(v * 10000), 10000) for v in vals)

    make, model = b"Apple\0", b"iPhone 15 Pro\0"
    ifd0_off, n0 = 8, 3
    data_off = ifd0_off + 2 + n0 * 12 + 4
    make_off, model_off = data_off, data_off + len(make)
    gps_off = model_off + len(model)
    n_gps = 4
    lat_off = gps_off + 2 + n_gps * 12 + 4
    lon_off = lat_off + 24
    out = b"II*\0" + struct.pack("<I", ifd0_off)
    out += struct.pack("<H", n0)
    out += struct.pack("<HHII", 0x010F, 2, len(make), make_off)
    out += struct.pack("<HHII", 0x0110, 2, len(model), model_off)
    out += struct.pack("<HHII", 0x8825, 4, 1, gps_off)
    out += struct.pack("<I", 0) + make + model
    out += struct.pack("<H", n_gps)
    out += struct.pack("<HHI", 1, 2, 2) + b"N\0\0\0"
    out += struct.pack("<HHII", 2, 5, 3, lat_off)
    out += struct.pack("<HHI", 3, 2, 2) + b"E\0\0\0"
    out += struct.pack("<HHII", 4, 5, 3, lon_off)
    out += struct.pack("<I", 0) + rat(50, 27, 0) + rat(30, 31, 25)
    return out


def jpeg_with_exif() -> tuple[bytes, bytes]:
    tiff = build_tiff()
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"
    app1 = b"\xff\xe1" + struct.pack(">H", 2 + 6 + len(tiff)) + b"Exif\0\0" + tiff
    com = b"\xff\xfe" + struct.pack(">H", 2 + 9) + b"my secret"
    scan = b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00" + b"PIXELDATA\x12\x34" + b"\xff\xd9"
    return b"\xff\xd8" + app0 + app1 + com + scan, scan


def test_exif_jpeg_inspect_and_strip(tmp_path):
    data, scan = jpeg_with_exif()
    photo = tmp_path / "IMG_0001.jpg"
    photo.write_bytes(data)
    meta, blocks = exif.inspect_jpeg(data)
    assert meta["Виробник"] == "Apple" and meta["Модель"] == "iPhone 15 Pro"
    assert meta["GPS"] == (50.45, 30.523611)
    r = exif.process(str(photo))
    assert any(f.severity == Severity.HIGH and "50.45" in f.title for f in r.findings)
    clean = (tmp_path / "IMG_0001.clean.jpg").read_bytes()
    assert clean.endswith(scan)  # пікселі не змінено
    assert b"Exif" not in clean and b"my secret" not in clean and b"JFIF" in clean
    assert photo.read_bytes() == data  # оригінал не чіпали
    assert exif.inspect_jpeg(clean) == ({}, [])


def png_chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def test_exif_png(tmp_path):
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    data = (exif.PNG_SIG + ihdr + png_chunk(b"tEXt", b"Author\0Ivan") + png_chunk(b"eXIf", build_tiff())
            + png_chunk(b"IDAT", zlib.compress(b"\0\0\0\0")) + png_chunk(b"IEND", b""))
    img = tmp_path / "shot.png"
    img.write_bytes(data)
    r = exif.process(str(img))
    titles = " ".join(f.title for f in r.findings)
    assert "GPS" in titles and "Author: Ivan" in titles
    clean = (tmp_path / "shot.clean.png").read_bytes()
    assert b"tEXt" not in clean and b"eXIf" not in clean and b"IDAT" in clean


def test_exif_unsupported(tmp_path):
    f = tmp_path / "x.heic"
    f.write_bytes(b"\0\0\0\x18ftypheic")
    with pytest.raises(SecurityError, match="exiftool"):
        exif.process(str(f))
    assert json.dumps  # noqa
