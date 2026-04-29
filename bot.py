import asyncio
import json
import os
import random
import secrets
import sqlite3
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message
from dotenv import load_dotenv
from aiohttp import web

# =========================
# Config
# =========================
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_ID = 8731647972
DB_PATH = Path("dashboard.db")
TARGETS_FILE = Path("targets.txt")
ACTIVE_PROXIES_FILE = Path("active_proxies.json")

GOOGLE_SUGGEST = "https://suggestqueries.google.com/complete/search"
SEARCH_ENDPOINT = "https://duckduckgo.com/html/"

DORK_FOOTPRINTS = [
    "cart.php?id=",
    "checkout.php?id=",
    "view_item.php?id=",
]
DB_ERRORS = ["SQL syntax", "MariaDB", "MySQL", "PostgreSQL"]


@dataclass
class License:
    key: str
    redeemed_by: int | None
    active: int


# =========================
# Database
# =========================
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            redeemed_by INTEGER,
            active INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            license_key TEXT,
            redeemed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def create_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    token = "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4))
    conn = db()
    conn.execute("INSERT INTO licenses(key, active) VALUES(?,0)", (token,))
    conn.commit()
    conn.close()
    return token


def redeem_key(user_id: int, key: str) -> tuple[bool, str]:
    conn = db()
    row = conn.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
    if not row:
        conn.close()
        return False, "Invalid key."
    if row["active"] == 1:
        conn.close()
        return False, "Key already redeemed."
    conn.execute("UPDATE licenses SET active=1, redeemed_by=? WHERE key=?", (user_id, key))
    conn.execute(
        "INSERT OR REPLACE INTO users(user_id, license_key) VALUES(?,?)",
        (user_id, key),
    )
    conn.commit()
    conn.close()
    return True, "License activated."


def user_status(user_id: int) -> str:
    conn = db()
    row = conn.execute(
        "SELECT u.user_id, u.license_key, l.active FROM users u JOIN licenses l ON u.license_key=l.key WHERE u.user_id=?",
        (user_id,),
    ).fetchone()
    conn.close()
    if not row:
        return "No active license linked to your account."
    return f"User: {row['user_id']}\nLicense: {row['license_key']}\nActive: {bool(row['active'])}"


# =========================
# Auth / Guards
# =========================
def is_admin(message: Message) -> bool:
    return message.from_user and message.from_user.id == ADMIN_ID


def ensure_admin(message: Message) -> bool:
    return bool(is_admin(message))


# =========================
# Proxy layer
# =========================
def load_active_proxies() -> list[str]:
    if not ACTIVE_PROXIES_FILE.exists():
        return []
    return json.loads(ACTIVE_PROXIES_FILE.read_text())


def save_active_proxies(proxies: list[str]) -> None:
    ACTIVE_PROXIES_FILE.write_text(json.dumps(proxies, indent=2))


async def validate_proxy(proxy: str) -> bool:
    try:
        async with httpx.AsyncClient(proxy=proxy, timeout=8.0, follow_redirects=True) as client:
            r = await client.get("https://www.google.com")
            return r.status_code < 500
    except Exception:
        return False


async def require_proxies() -> bool:
    return len(load_active_proxies()) > 0


# =========================
# Recon modules
# =========================
async def keyword_expand(seed: str) -> list[str]:
    out = set()
    async with httpx.AsyncClient(timeout=12.0) as client:
        for c in string.ascii_lowercase:
            q = f"{seed} {c}"
            params = {"client": "firefox", "q": q}
            try:
                r = await client.get(GOOGLE_SUGGEST, params=params)
                data = r.json()
                suggestions = data[1] if isinstance(data, list) and len(data) > 1 else []
                out.update(suggestions)
            except Exception:
                continue
    return sorted(out)


def dork_map(keywords: Iterable[str]) -> list[str]:
    dorks = []
    for kw in keywords:
        for fp in DORK_FOOTPRINTS:
            dorks.append(f'"{kw}" "{fp}"')
    return dorks


async def index_search(dorks: list[str], proxies: list[str]) -> set[str]:
    urls: set[str] = set()
    for i, dork in enumerate(dorks):
        proxy = proxies[i % len(proxies)]
        try:
            async with httpx.AsyncClient(proxy=proxy, timeout=12.0) as client:
                r = await client.get(SEARCH_ENDPOINT, params={"q": dork})
                # quick extractor (not perfect)
                parts = r.text.split('href="')
                for p in parts[1:]:
                    u = p.split('"', 1)[0]
                    if u.startswith("http"):
                        urls.add(u)
        except Exception:
            continue
    TARGETS_FILE.write_text("\n".join(sorted(urls)))
    return urls


# =========================
# Analyzer
# =========================
def fuzz_quote(url: str) -> str:
    s = urlsplit(url)
    qs = parse_qsl(s.query, keep_blank_values=True)
    if not qs:
        return url
    fuzzed = [(k, v + "'") for k, v in qs]
    return urlunsplit((s.scheme, s.netloc, s.path, urlencode(fuzzed), s.fragment))


async def analyze_urls(urls: list[str], proxies: list[str], msg: Message) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    total = len(urls)
    for idx, u in enumerate(urls, 1):
        proxy = proxies[idx % len(proxies)]
        test_url = fuzz_quote(u)
        try:
            async with httpx.AsyncClient(proxy=proxy, timeout=10.0) as client:
                r = await client.get(test_url)
                body = r.text
                for sig in DB_ERRORS:
                    if sig.lower() in body.lower():
                        findings.append((u, sig))
                        break
        except Exception:
            pass
        done = int((idx / total) * 5)
        bar = "▓" * done + "░" * (5 - done)
        await msg.answer(f"Progress: [{bar}] {idx}/{total}")
    return findings




async def start_web_server() -> web.AppRunner:
    async def health(_: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    app = web.Application()
    app.router.add_get("/", health)
    app.router.add_get("/health", health)

    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.environ.get("PORT", "10000"))
    site = web.TCPSite(runner, host="0.0.0.0", port=port)
    await site.start()
    print(f"[web] health server listening on 0.0.0.0:{port}", flush=True)
    return runner

# =========================
# Bot handlers
# =========================
dp = Dispatcher()


@dp.message(Command("start"))
async def start(m: Message):
    if not ensure_admin(m):
        await m.answer("Unauthorized.")
        return
    await m.answer("Bug Bounty Intelligence Dashboard bot online.")


@dp.message(Command("gen"))
async def gen(m: Message):
    if not ensure_admin(m):
        await m.answer("Unauthorized.")
        return
    key = create_key()
    await m.answer(f"New license key:\n`{key}`")


@dp.message(Command("redeem"))
async def redeem(m: Message):
    if not ensure_admin(m):
        await m.answer("Unauthorized.")
        return
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await m.answer("Usage: /redeem <LICENSE_KEY>")
        return
    ok, text = redeem_key(m.from_user.id, parts[1].strip())
    await m.answer(text)


@dp.message(Command("status"))
async def status(m: Message):
    if not ensure_admin(m):
        await m.answer("Unauthorized.")
        return
    await m.answer(user_status(m.from_user.id))


@dp.message(Command("proxytest"))
async def proxytest(m: Message):
    if not ensure_admin(m):
        await m.answer("Unauthorized.")
        return
    lines = [x.strip() for x in (m.text or "").splitlines()[1:] if x.strip()]
    if not lines:
        await m.answer("Send /proxytest and put one proxy per line below command.")
        return
    valid = []
    for p in lines:
        if await validate_proxy(p):
            valid.append(p)
    save_active_proxies(valid)
    await m.answer(f"Valid proxies: {len(valid)}/{len(lines)}")


@dp.message(Command("recon"))
async def recon(m: Message):
    if not ensure_admin(m):
        await m.answer("Unauthorized.")
        return
    if not await require_proxies():
        await m.answer("No active proxies. Run /proxytest first.")
        return
    seed = (m.text or "").replace("/recon", "", 1).strip()
    if not seed:
        await m.answer("Usage: /recon <seed keyword>")
        return
    proxies = load_active_proxies()
    kws = await keyword_expand(seed)
    dorks = dork_map(kws)
    urls = await index_search(dorks, proxies)
    await m.answer(f"Recon completed. Unique targets saved: {len(urls)} -> {TARGETS_FILE}")


@dp.message(Command("analyze"))
async def analyze(m: Message):
    if not ensure_admin(m):
        await m.answer("Unauthorized.")
        return
    if not await require_proxies():
        await m.answer("No active proxies. Run /proxytest first.")
        return
    if not TARGETS_FILE.exists():
        await m.answer("targets.txt not found. Run /recon first.")
        return
    urls = [u.strip() for u in TARGETS_FILE.read_text().splitlines() if u.strip()]
    proxies = load_active_proxies()
    findings = await analyze_urls(urls, proxies, m)
    if findings:
        report = "\n".join(f"- {u} | Signature: {sig}" for u, sig in findings)
    else:
        report = "No SQL error signatures detected."
    await m.answer("Vulnerability Report:\n" + report)


async def main():
    init_db()
    runner = await start_web_server()

    if not BOT_TOKEN:
        print("[bot] BOT_TOKEN is not set; health server remains active.", flush=True)
        await asyncio.Event().wait()

    bot = Bot(BOT_TOKEN)
    try:
        await dp.start_polling(bot)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
