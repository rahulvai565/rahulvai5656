#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Thordata Proxy Management Telegram Bot
======================================
শুধুমাত্র Thordata-র ডকুমেন্টেড Public API (https://openapi.thordata.com/api) ব্যবহার করে:

  GET  /account/traffic-balance        -> মূল অ্যাকাউন্টের অবশিষ্ট ট্রাফিক
  GET  /account/wallet-balance         -> ওয়ালেট ব্যালেন্স
  GET  /account/usage-statistics       -> মূল অ্যাকাউন্টের ব্যবহার (KB)
  GET  /proxy-users/user-list          -> Proxy sub-user তালিকা (MB)
  POST /proxy-users/create-user        -> Proxy sub-user তৈরি (traffic_limit MB)
  POST /proxy-users/delete-user        -> Proxy sub-user মুছে ফেলা
  GET  /proxy-users/usage-statistics   -> sub-user এর limit / used / balance (KB)

গুরুত্বপূর্ণ বাস্তবতা:
  * "Proxy তৈরি" = Thordata-তে একটি proxy sub-user তৈরি + sticky-session proxy লাইন জেনারেট।
  * Quantity  = একই sub-user থেকে আলাদা sessid সহ কয়টি IP/লাইন।
  * Duration  = sticky session এর সময় (মিনিট)  -> Thordata proxy-তে `sesstime`।
  * Traffic Limit = API-র `traffic_limit` (MB, ন্যূনতম 100, 0 = আনলিমিটেড) -> Thordata নিজেই কার্যকর করে।
  * Package expiry / Creator quota / Max IP = সম্পূর্ণ বটের নিজস্ব নিয়ম (Thordata API এগুলো কার্যকর করে না)।
"""

import asyncio
import base64
import hashlib
import html
import io
import logging
import os
import re
import secrets
import string
import sys
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional

import httpx
from bson import ObjectId
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    Update,
)
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

load_dotenv()

# ──────────────────────────────── Config ────────────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
MONGO_URI = os.getenv("MONGO_URI", "").strip()
MONGO_DB = os.getenv("MONGO_DB", "thordata_bot").strip()
ADMIN_IDS = {int(x) for x in re.split(r"[,\s]+", os.getenv("ADMIN_IDS", "")) if x.strip().isdigit()}
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "").strip()

API_BASE = os.getenv("THORDATA_API_BASE", "https://openapi.thordata.com/api").rstrip("/")
PROXY_TYPE = int(os.getenv("PROXY_TYPE", "1"))  # 1 = Residential, 2 = Unlimited
PROXY_HOST = os.getenv("PROXY_HOST", "t.thordata.online")
PROXY_PORT = os.getenv("PROXY_PORT", "9999")
# Thordata ডক বলছে account traffic_balance = MB; কিছু সোর্সে KB লেখা। ভুল হলে .env-এ KB করুন।
TRAFFIC_BALANCE_UNIT = os.getenv("TRAFFIC_BALANCE_UNIT", "MB").upper()
MIN_TRAFFIC_MB = 100  # Thordata ডক অনুযায়ী ন্যূনতম

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=os.getenv("LOG_LEVEL", "INFO"),
)
log = logging.getLogger("thordata-bot")
logging.getLogger("httpx").setLevel(logging.WARNING)  # URL (token সহ) লগে আসা বন্ধ

db = None  # post_init-এ সেট হবে
th: "Thordata" = None  # type: ignore

HTML = ParseMode.HTML
ALNUM = string.ascii_lowercase + string.digits


# ──────────────────────────────── Helpers ────────────────────────────────
def now() -> datetime:
    return datetime.now(timezone.utc)


def esc(x: Any) -> str:
    return html.escape(str(x))


def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS


def fmt_mb(mb: Optional[float]) -> str:
    if mb is None:
        return "N/A"
    mb = float(mb)
    return f"{mb / 1024:.2f} GB" if mb >= 1024 else f"{mb:.2f} MB"


def fmt_kb(kb: Optional[float]) -> str:
    return "N/A" if kb is None else fmt_mb(float(kb) / 1024)


def fmt_dt(d: Optional[datetime]) -> str:
    return d.strftime("%Y-%m-%d") if d else "—"


def to_int(s: str, lo: int, hi: int) -> Optional[int]:
    s = s.strip()
    if not re.fullmatch(r"-?\d+", s):
        return None
    v = int(s)
    return v if lo <= v <= hi else None


def norm_username(s: str) -> Optional[str]:
    s = s.strip()
    if s.lower().startswith("td-customer-"):
        s = s[len("td-customer-"):]
    return s if re.fullmatch(r"[A-Za-z0-9_.\-]{2,40}", s) else None


def gen_username() -> str:
    return "tb" + "".join(secrets.choice(ALNUM) for _ in range(8))


def gen_password() -> str:
    return secrets.choice(string.ascii_lowercase) + "".join(secrets.choice(ALNUM) for _ in range(9))


def ikb(rows: list) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(t, callback_data=d) for t, d in r] for r in rows])


def oid(s: str) -> Optional[ObjectId]:
    try:
        return ObjectId(s)
    except Exception:
        return None


# ──────────────────────────────── Crypto / settings ────────────────────────────────
def _fernet() -> Fernet:
    key = ENCRYPTION_KEY
    if not key:
        log.warning("ENCRYPTION_KEY সেট করা নেই — BOT_TOKEN থেকে কী তৈরি হচ্ছে। .env-এ আলাদা কী দিন।")
        key = base64.urlsafe_b64encode(hashlib.sha256(BOT_TOKEN.encode()).digest()).decode()
    return Fernet(key.encode())


async def get_setting(key: str, default=None):
    d = await db.settings.find_one({"_id": key})
    return d["value"] if d else default


async def set_setting(key: str, value) -> None:
    await db.settings.update_one({"_id": key}, {"$set": {"value": value}}, upsert=True)


async def set_secret(key: str, value: str) -> None:
    await set_setting(key, _fernet().encrypt(value.encode()).decode())


async def get_secret(key: str) -> str:
    v = await get_setting(key)
    if not v:
        return ""
    try:
        return _fernet().decrypt(v.encode()).decode()
    except (InvalidToken, ValueError):
        log.error("সংরক্ষিত secret '%s' ডিক্রিপ্ট করা যায়নি (ENCRYPTION_KEY বদলেছে?)", key)
        return ""


async def admin_log(uid: int, action: str, detail: str = "") -> None:
    await db.admin_logs.insert_one({"ts": now(), "admin_id": uid, "action": action, "detail": detail})
    log.info("ADMIN %s | %s | %s", uid, action, detail)


# ──────────────────────────────── Thordata API client ────────────────────────────────
@dataclass
class R:
    ok: bool
    data: Any
    msg: str
    code: Optional[int] = None


class Thordata:
    def __init__(self) -> None:
        self.http = httpx.AsyncClient(timeout=30)

    async def creds(self) -> tuple[str, str]:
        token = await get_secret("api_token") or os.getenv("THORDATA_TOKEN", "")
        key = await get_secret("api_key") or os.getenv("THORDATA_KEY", "")
        return token.strip(), key.strip()

    async def request(self, method: str, path: str, *, params: dict = None, body: dict = None,
                      actor: int = 0, action: str = "") -> R:
        token, key = await self.creds()
        if not token:
            return R(False, None, "Thordata API Token সেট করা নেই।", None)
        headers = {"token": token}
        if key:
            headers["key"] = key
        try:
            if method == "GET":
                q = dict(params or {})
                q["token"] = token
                resp = await self.http.get(API_BASE + path, params=q, headers=headers)
            else:
                resp = await self.http.post(API_BASE + path, json=body or {}, headers=headers)
            js = resp.json()
        except Exception as e:  # নেটওয়ার্ক / JSON ত্রুটি — token যেন মেসেজে না আসে
            err = str(e).replace(token, "***")
            r = R(False, None, f"নেটওয়ার্ক/রেসপন্স ত্রুটি: {err[:200]}", None)
            await self._log(actor, action, path, r)
            return r
        code = js.get("code")
        r = R(code == 200, js.get("data"), str(js.get("msg", "")), code)
        await self._log(actor, action, path, r)
        return r

    async def _log(self, actor: int, action: str, path: str, r: R) -> None:
        try:
            await db.api_logs.insert_one({"ts": now(), "actor": actor, "action": action, "path": path,
                                          "ok": r.ok, "code": r.code, "msg": r.msg[:200]})
        except Exception:
            log.exception("api_logs লেখা যায়নি")

    # ডকুমেন্টেড এন্ডপয়েন্ট র‍্যাপার
    async def traffic_balance(self, actor=0):
        return await self.request("GET", "/account/traffic-balance", actor=actor, action="account_traffic_balance")

    async def wallet_balance(self, actor=0):
        return await self.request("GET", "/account/wallet-balance", actor=actor, action="account_wallet_balance")

    async def account_usage(self, days=30, actor=0):
        t = date.today()
        return await self.request("GET", "/account/usage-statistics", actor=actor, action="account_usage",
                                  params={"from_date": (t - timedelta(days=days - 1)).isoformat(),
                                          "to_date": t.isoformat()})

    async def user_list(self, actor=0):
        return await self.request("GET", "/proxy-users/user-list", actor=actor, action="user_list",
                                  params={"proxy_type": PROXY_TYPE})

    async def user_usage(self, username, days=7, actor=0):
        t = date.today()
        return await self.request("GET", "/proxy-users/usage-statistics", actor=actor, action="user_usage",
                                  params={"proxy_type": PROXY_TYPE, "username": username,
                                          "from_date": (t - timedelta(days=days - 1)).isoformat(),
                                          "to_date": t.isoformat()})

    async def create_user(self, username, password, traffic_mb, actor=0):
        return await self.request("POST", "/proxy-users/create-user", actor=actor, action="create_user",
                                  body={"proxy_type": PROXY_TYPE, "username": username, "password": password,
                                        "traffic_limit": traffic_mb, "status": "true"})

    async def delete_user(self, username, actor=0):
        return await self.request("POST", "/proxy-users/delete-user", actor=actor, action="delete_user",
                                  body={"proxy_type": PROXY_TYPE, "username": username})


# ──────────────────────────────── Roles / quota ────────────────────────────────
async def get_creator(uid: int) -> Optional[dict]:
    return await db.creators.find_one({"_id": uid})


def creator_problem(c: Optional[dict]) -> str:
    """খালি স্ট্রিং = ঠিক আছে; নইলে কারণ।"""
    if not c:
        return "আপনার Creator Permission নেই।"
    if c.get("blocked"):
        return "আপনার Creator অ্যাকাউন্ট ব্লক করা আছে।"
    if c.get("expiry") and c["expiry"] < now():
        return "আপনার প্যাকেজের মেয়াদ শেষ।"
    if not c.get("package_id"):
        return "আপনাকে কোনো প্যাকেজ দেওয়া হয়নি।"
    return ""


async def package_of(c: dict) -> Optional[dict]:
    return await db.packages.find_one({"_id": c["package_id"]}) if c.get("package_id") else None


async def main_keyboard(uid: int) -> ReplyKeyboardMarkup:
    rows = [[BTN_BAL, BTN_SUP]]
    if is_admin(uid):
        rows += [[BTN_ADMIN, BTN_CREATE], [BTN_CBAL]]
    else:
        c = await get_creator(uid)
        if c and not c.get("blocked"):
            rows.append([BTN_CREATE, BTN_MYPKG])
            if c.get("can_check_balance"):
                rows.append([BTN_CBAL])
    return ReplyKeyboardMarkup(rows, resize_keyboard=True)


BTN_BAL = "📊 Check Balance"
BTN_SUP = "🆘 Support"
BTN_ADMIN = "👑 Admin Panel"
BTN_CREATE = "🌐 Create IP/Proxy"
BTN_MYPKG = "📦 My Package"
BTN_CBAL = "🔍 Check Username Balance"
MENU_TEXTS = {BTN_BAL, BTN_SUP, BTN_ADMIN, BTN_CREATE, BTN_MYPKG, BTN_CBAL}


# ──────────────────────────────── Send helpers ────────────────────────────────
async def reply(update: Update, text: str, kb=None) -> None:
    await update.effective_chat.send_message(text, parse_mode=HTML, reply_markup=kb,
                                             disable_web_page_preview=True)


async def show(update: Update, text: str, kb=None) -> None:
    """Callback হলে মেসেজ এডিট, নইলে নতুন মেসেজ।"""
    q = update.callback_query
    if q:
        try:
            await q.edit_message_text(text, parse_mode=HTML, reply_markup=kb, disable_web_page_preview=True)
            return
        except BadRequest as e:
            if "not modified" in str(e).lower():
                return
    await reply(update, text, kb)


# ──────────────────────────────── Balance text ────────────────────────────────
async def user_balance_text(username: str, actor: int, detailed: bool) -> str:
    r = await th.user_usage(username, actor=actor)
    if not r.ok:
        if detailed:
            return f"❌ API Error: <code>{esc(r.msg)}</code> (code: {esc(r.code)})"
        if r.code is None:
            return "❌ সার্ভারের সঙ্গে যোগাযোগ করা যাচ্ছে না। কিছুক্ষণ পরে চেষ্টা করুন।"
        return "❌ Username পাওয়া যায়নি। সঠিক Proxy Username দিয়ে আবার চেষ্টা করুন।"
    d = r.data or {}
    limit_kb = d.get("traffic_limit") or 0
    used_kb = d.get("total_usage_traffic")
    bal_kb = d.get("traffic_balance")
    out = [f"✅ <b>Username:</b> <code>{esc(username)}</code>", ""]
    if limit_kb == 0:
        out.append("📦 Limit: <b>Unlimited</b>")
        out.append(f"📉 ব্যবহৃত: <b>{fmt_kb(used_kb)}</b>")
        out.append("📊 অবশিষ্ট: <b>Unlimited (মূল অ্যাকাউন্ট ব্যালেন্স থেকে)</b>")
    else:
        out.append(f"📦 Limit: <b>{fmt_kb(limit_kb)}</b>")
        out.append(f"📉 ব্যবহৃত: <b>{fmt_kb(used_kb)}</b>")
        out.append(f"📊 অবশিষ্ট: <b>{fmt_kb(bal_kb)}</b>")
    if d.get("range_usage_traffic") is not None:
        out.append(f"🗓️ গত {d.get('query_days', 7)} দিনে: {fmt_kb(d['range_usage_traffic'])}")
    if detailed:
        lr = await th.user_list(actor=actor)
        if lr.ok:
            for u in (lr.data or {}).get("list", []):
                if u.get("username") == username:
                    out.append(f"⚙️ Status: {'Enabled ✅' if u.get('status') else 'Disabled 🚫'}")
                    out.append(f"🕒 তৈরি: {esc(u.get('created_time', '—'))}")
                    break
    return "\n".join(out)


# ──────────────────────────────── Commands / menus ────────────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    ctx.user_data.clear()
    uid = update.effective_user.id
    if await maintenance_block(update, uid):
        return
    await reply(update, "👋 স্বাগতম! নিচের বাটন থেকে অপশন বেছে নিন।", await main_keyboard(uid))


async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    ctx.user_data.clear()
    await reply(update, "❎ বাতিল করা হয়েছে।", await main_keyboard(update.effective_user.id))


async def cmd_panel(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if is_admin(update.effective_user.id):
        await send_admin_panel(update)


async def maintenance_block(update: Update, uid: int) -> bool:
    if not is_admin(uid) and await get_setting("maintenance", False):
        await reply(update, "🛠️ বট সাময়িকভাবে রক্ষণাবেক্ষণে আছে। পরে চেষ্টা করুন।")
        return True
    return False


ADMIN_MENU = [
    [("🔑 API Token Settings", "a:tok")],
    [("🌐 Create IP/Proxy", "p:new")],
    [("📦 Package Management", "k:menu")],
    [("👥 Creator Management", "c:menu"), ("📋 Creator List", "c:l:v:0")],
    [("🔍 Check Any Username Balance", "a:cbal")],
    [("📊 Website Traffic Balance", "a:web")],
    [("📈 Usage Report", "a:rep")],
    [("🗑️ Delete/Disable Creator", "c:l:d:0")],
    [("🆘 Support Settings", "a:sup")],
    [("⚙️ Bot Settings", "a:set")],
]


async def send_admin_panel(update: Update) -> None:
    await show(update, "👑 <b>Main Admin Panel</b>", ikb(ADMIN_MENU))


async def route_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    uid = update.effective_user.id
    if text == BTN_BAL:
        ctx.user_data["st"] = {"n": "bal"}
        await reply(update, "🔎 আপনার <b>Proxy Username</b> লিখে পাঠান।\n(বাতিল: /cancel)")
    elif text == BTN_SUP:
        txt = await get_setting("support_text", "Support তথ্য এখনো সেট করা হয়নি। Admin-এর সঙ্গে যোগাযোগ করুন।")
        await reply(update, f"🆘 <b>Support</b>\n\n{esc(txt)}")
    elif text == BTN_ADMIN and is_admin(uid):
        await send_admin_panel(update)
    elif text == BTN_CREATE:
        await start_create(update, ctx)
    elif text == BTN_MYPKG:
        c = await get_creator(uid)
        if c:
            await reply(update, await creator_text(c, short=True))
    elif text == BTN_CBAL:
        c = await get_creator(uid)
        if is_admin(uid) or (c and not c.get("blocked") and c.get("can_check_balance")):
            ctx.user_data["st"] = {"n": "cbal"}
            await reply(update, "🔎 যেকোনো <b>Proxy Username</b> লিখে পাঠান।\n(বাতিল: /cancel)")


# ──────────────────────────────── Creator text ────────────────────────────────
async def creator_text(c: dict, short: bool = False) -> str:
    pkg = await package_of(c)
    status = "🚫 Blocked" if c.get("blocked") else ("⏳ Expired" if c.get("expiry") and c["expiry"] < now() else "✅ Active")
    lines = [f"👤 <b>{esc(c.get('name') or c['_id'])}</b> (<code>{c['_id']}</code>)", f"Status: {status}"]
    if pkg:
        lines += [
            f"📦 Package: <b>{esc(pkg['name'])}</b>",
            f"⏳ মেয়াদ: {fmt_dt(c.get('expiry'))}",
            f"🔢 IP ব্যবহার: {c.get('proxies_created', 0)} / {pkg['max_ip']}",
            f"📊 Traffic বরাদ্দ: {fmt_mb(c.get('traffic_allocated_mb', 0))} / {fmt_mb(pkg['traffic_mb'])}",
        ]
    else:
        lines.append("📦 Package: নেই")
    if not short:
        lines.append(f"🔍 Balance চেক: {'অনুমোদিত' if c.get('can_check_balance') else 'নেই'}")
    return "\n".join(lines)


# ──────────────────────────────── Text router ────────────────────────────────
async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text:
        return
    uid = update.effective_user.id
    text = update.message.text.strip()
    if await maintenance_block(update, uid):
        return
    if text in MENU_TEXTS:
        ctx.user_data.pop("st", None)
        await route_menu(update, ctx, text)
        return
    st = ctx.user_data.get("st")
    if st:
        await handle_state(update, ctx, st, text)


_cooldown: dict[int, float] = {}


async def handle_state(update: Update, ctx: ContextTypes.DEFAULT_TYPE, st: dict, text: str) -> None:
    uid = update.effective_user.id
    n = st["n"]

    # ───── সাধারণ ইউজার: Check Balance ─────
    if n == "bal":
        if time.time() - _cooldown.get(uid, 0) < 3:
            await reply(update, "⏳ একটু অপেক্ষা করে আবার চেষ্টা করুন।")
            return
        _cooldown[uid] = time.time()
        uname = norm_username(text)
        if not uname:
            await reply(update, "❌ Username ফরম্যাট সঠিক নয়। আবার লিখুন (বাতিল: /cancel)।")
            return
        ctx.user_data.pop("st", None)
        await reply(update, await user_balance_text(uname, uid, detailed=False))
        return

    # ───── Admin / অনুমোদিত Creator: যেকোনো username ─────
    if n == "cbal":
        c = await get_creator(uid)
        if not (is_admin(uid) or (c and not c.get("blocked") and c.get("can_check_balance"))):
            ctx.user_data.pop("st", None)
            return
        uname = norm_username(text)
        if not uname:
            await reply(update, "❌ Username ফরম্যাট সঠিক নয়।")
            return
        ctx.user_data.pop("st", None)
        await reply(update, await user_balance_text(uname, uid, detailed=True))
        return

    # ───── Proxy তৈরির ধাপ ─────
    if n.startswith("p_"):
        await state_create(update, ctx, st, text)
        return

    # নিচের সব স্টেট শুধু Admin-এর
    if not is_admin(uid):
        ctx.user_data.pop("st", None)
        return

    if n == "tok_set":
        await safe_delete(update)
        ctx.user_data["st"] = {"n": "tok_key", "token": text}
        await reply(update, "🔐 এবার Thordata <b>Public Key</b> পাঠান (না থাকলে <code>-</code> লিখুন)।\n"
                            "<i>বার্তাটি নিরাপত্তার জন্য মুছে ফেলা হবে।</i>")
        return

    if n == "tok_key":
        await safe_delete(update)
        token = st["token"]
        await set_secret("api_token", token)
        await set_secret("api_key", "" if text == "-" else text)
        ctx.user_data.pop("st", None)
        await admin_log(uid, "set_api_token", "token updated")
        await reply(update, "✅ Token এনক্রিপ্ট করে সংরক্ষণ করা হয়েছে। কানেকশন টেস্ট হচ্ছে...")
        await reply(update, await test_connection_text(uid))
        return

    if n == "k_add":
        await state_package_add(update, ctx, st, text)
        return

    if n == "k_edit":
        await state_package_edit(update, ctx, st, text)
        return

    if n == "c_add_id":
        v = to_int(text, 1, 10 ** 15)
        if v is None:
            await reply(update, "❌ সঠিক Telegram User ID (সংখ্যা) দিন।")
            return
        if is_admin(v):
            await reply(update, "ℹ️ ইনি Main Admin — Creator বানানো দরকার নেই।")
            return
        if await get_creator(v):
            await reply(update, "ℹ️ এই ইউজার আগে থেকেই Creator।")
            ctx.user_data.pop("st", None)
            return
        ctx.user_data["st"] = {"n": "c_add_name", "uid": v}
        await reply(update, "✏️ Creator-এর নাম লিখুন (বাদ দিতে <code>-</code>)।")
        return

    if n == "c_add_name":
        name = "" if text == "-" else text[:50]
        pkgs = await db.packages.find().to_list(50)
        rows = [[(f"📦 {p['name']}", f"c:addpk:{p['_id']}")] for p in pkgs]
        rows.append([("➡️ প্যাকেজ ছাড়া তৈরি", "c:addpk:none")])
        ctx.user_data["st"] = {"n": "c_add_pick", "uid": st["uid"], "name": name}
        await reply(update, "📦 প্যাকেজ বেছে নিন:", ikb(rows))
        return

    if n == "c_exp":
        d = to_int(text, 0, 3650)
        if d is None:
            await reply(update, "❌ ০–৩৬৫০ এর মধ্যে দিন সংখ্যা দিন (০ = মেয়াদহীন)।")
            return
        exp = now() + timedelta(days=d) if d else None
        await db.creators.update_one({"_id": st["uid"]}, {"$set": {"expiry": exp}})
        await admin_log(uid, "set_expiry", f"creator={st['uid']} days={d}")
        ctx.user_data.pop("st", None)
        c = await get_creator(st["uid"])
        await reply(update, "✅ মেয়াদ আপডেট হয়েছে।\n\n" + await creator_text(c), ikb(creator_buttons(c)))
        return

    if n == "c_search":
        ctx.user_data.pop("st", None)
        if re.fullmatch(r"\d+", text):
            q = {"_id": int(text)}
        else:
            q = {"name": {"$regex": re.escape(text), "$options": "i"}}
        res = await db.creators.find(q).to_list(20)
        if not res:
            await reply(update, "🔍 কিছু পাওয়া যায়নি।", ikb([[("⬅️ Creator Menu", "c:menu")]]))
            return
        rows = [[(f"👤 {c.get('name') or c['_id']} ({c['_id']})", f"c:v:{c['_id']}")] for c in res]
        rows.append([("⬅️ Back", "c:menu")])
        await reply(update, f"🔍 {len(res)} টি ফলাফল:", ikb(rows))
        return

    if n == "sup_edit":
        await set_setting("support_text", text[:1500])
        await admin_log(uid, "support_text", "updated")
        ctx.user_data.pop("st", None)
        await reply(update, "✅ Support তথ্য আপডেট হয়েছে।", ikb([[("⬅️ Admin Panel", "a:menu")]]))
        return

    if n == "set_val":
        key = st["key"]
        lo, hi = {"max_qty": (1, 500), "max_session": (1, 1440)}[key]
        v = to_int(text, lo, hi)
        if v is None:
            await reply(update, f"❌ {lo}–{hi} এর মধ্যে সংখ্যা দিন।")
            return
        await set_setting(key, v)
        await admin_log(uid, "bot_setting", f"{key}={v}")
        ctx.user_data.pop("st", None)
        await reply(update, "✅ সেভ হয়েছে।", ikb([[("⚙️ Bot Settings", "a:set")]]))
        return


async def safe_delete(update: Update) -> None:
    try:
        await update.message.delete()
    except Exception:
        pass


# ──────────────────────────────── Connection test / web balance ────────────────────────────────
async def test_connection_text(actor: int) -> str:
    token, _ = await th.creds()
    if not token:
        return "❌ কোনো API Token সেট করা নেই।"
    r = await th.traffic_balance(actor)
    if r.ok:
        return "✅ <b>API Connection OK</b> — Thordata সফলভাবে সংযুক্ত।"
    return f"❌ <b>API Connection ব্যর্থ</b>\nCode: {esc(r.code)}\nMessage: <code>{esc(r.msg)}</code>"


def account_balance_mb(raw) -> Optional[float]:
    if raw is None:
        return None
    return float(raw) / 1024 if TRAFFIC_BALANCE_UNIT == "KB" else float(raw)


async def web_balance_text(actor: int) -> str:
    tb, wb, au, ul = await asyncio.gather(th.traffic_balance(actor), th.wallet_balance(actor),
                                          th.account_usage(30, actor), th.user_list(actor))
    out = ["📊 <b>Thordata Website Traffic Balance</b>", ""]
    if tb.ok:
        d = tb.data or {}
        out.append(f"📦 অবশিষ্ট Traffic: <b>{fmt_mb(account_balance_mb(d.get('traffic_balance')))}</b>")
        out.append(f"   <i>(raw: {esc(d.get('traffic_balance'))}, unit: {TRAFFIC_BALANCE_UNIT})</i>")
        out.append(f"⏳ মেয়াদ: {esc(d.get('expiration_time', '—'))}")
    else:
        out.append(f"📦 Traffic Balance: ❌ {esc(tb.msg)}")
    if au.ok:
        d = au.data or {}
        out.append(f"📉 মোট ব্যবহৃত (API): <b>{fmt_kb(d.get('total_usage_traffic'))}</b>")
        out.append(f"🗓️ গত ৩০ দিনে: {fmt_kb(d.get('range_usage_traffic'))}")
        if d.get("traffic_balance") is not None:
            out.append(f"📊 Usage API-র ব্যালেন্স: {fmt_kb(d.get('traffic_balance'))}")
    else:
        out.append(f"📉 Usage: ❌ {esc(au.msg)}")
    if wb.ok:
        out.append(f"💰 Wallet: <b>{esc((wb.data or {}).get('wallet_balance'))}</b>")
    else:
        out.append(f"💰 Wallet: ❌ {esc(wb.msg)}")
    if ul.ok:
        d = ul.data or {}
        out.append(f"👥 Proxy Users: {d.get('user_count')} (বাকি স্লট: {d.get('remaining_limit')} / {d.get('limit')})")
    out += ["", "<i>ℹ️ API শুধু অবশিষ্ট ও ব্যবহৃত দেয়; 'মোট কেনা' আলাদা করে দেয় না, তাই তা দেখানো হয়নি।</i>"]
    return "\n".join(out)


# ──────────────────────────────── Proxy creation ────────────────────────────────
async def start_create(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id
    if not is_admin(uid):
        c = await get_creator(uid)
        why = creator_problem(c)
        if why:
            await show(update, f"⛔ {why}")
            return
    ctx.user_data["st"] = {"n": "p_cc"}
    await show(update, "🌍 <b>Country code</b> লিখুন (যেমন <code>us</code>, <code>gb</code>, <code>bd</code>) "
                       "অথবা র‍্যান্ডম দেশের জন্য <code>any</code>।\n(বাতিল: /cancel)")


async def create_limits(uid: int) -> tuple[int, int, str]:
    """(max_qty, max_traffic_mb, error) — Admin-এর জন্য traffic সীমাহীন = -1"""
    max_qty_cfg = await get_setting("max_qty", 50)
    if is_admin(uid):
        return max_qty_cfg, -1, ""
    c = await get_creator(uid)
    why = creator_problem(c)
    if why:
        return 0, 0, why
    pkg = await package_of(c)
    if not pkg:
        return 0, 0, "আপনার প্যাকেজ খুঁজে পাওয়া যায়নি।"
    rem_ip = pkg["max_ip"] - c.get("proxies_created", 0)
    rem_tr = pkg["traffic_mb"] - c.get("traffic_allocated_mb", 0)
    if rem_ip <= 0:
        return 0, 0, "প্যাকেজের IP সীমা শেষ।"
    if rem_tr < MIN_TRAFFIC_MB:
        return 0, 0, f"প্যাকেজের Traffic সীমা শেষ (অবশিষ্ট {fmt_mb(max(rem_tr, 0))}, ন্যূনতম {MIN_TRAFFIC_MB} MB লাগে)।"
    return min(rem_ip, max_qty_cfg), rem_tr, ""


async def state_create(update: Update, ctx: ContextTypes.DEFAULT_TYPE, st: dict, text: str) -> None:
    uid = update.effective_user.id
    n = st["n"]
    max_qty, max_tr, err = await create_limits(uid)
    if err:
        ctx.user_data.pop("st", None)
        await reply(update, f"⛔ {err}")
        return

    if n == "p_cc":
        t = text.lower()
        if t == "any":
            cc = ""
        elif re.fullmatch(r"[a-z]{2}", t):
            cc = t
        else:
            await reply(update, "❌ ২ অক্ষরের country code (যেমন us) অথবা any লিখুন।")
            return
        ctx.user_data["st"] = {"n": "p_qty", "cc": cc}
        await reply(update, f"🔢 <b>Quantity</b> (কয়টি IP/লাইন)? সর্বোচ্চ {max_qty}")
    elif n == "p_qty":
        v = to_int(text, 1, max_qty)
        if v is None:
            await reply(update, f"❌ ১–{max_qty} এর মধ্যে সংখ্যা দিন।")
            return
        st["qty"] = v
        st["n"] = "p_min"
        ms = await get_setting("max_session", 120)
        await reply(update, f"⏳ <b>Duration</b> — sticky session কত মিনিট? (১–{ms})")
    elif n == "p_min":
        ms = await get_setting("max_session", 120)
        v = to_int(text, 1, ms)
        if v is None:
            await reply(update, f"❌ ১–{ms} এর মধ্যে মিনিট দিন।")
            return
        st["mins"] = v
        st["n"] = "p_tr"
        if max_tr == -1:
            hint = f"ন্যূনতম {MIN_TRAFFIC_MB} MB, <code>0</code> = আনলিমিটেড"
        else:
            hint = f"{MIN_TRAFFIC_MB}–{max_tr} MB"
        await reply(update, f"📊 <b>Traffic Limit</b> (MB)? {hint}")
    elif n == "p_tr":
        if max_tr == -1:
            v = to_int(text, 0, 10 ** 7)
            valid = v is not None and (v == 0 or v >= MIN_TRAFFIC_MB)
        else:
            v = to_int(text, MIN_TRAFFIC_MB, max_tr)
            valid = v is not None
        if not valid:
            await reply(update, f"❌ সঠিক মান দিন (ন্যূনতম {MIN_TRAFFIC_MB} MB"
                                f"{'' if max_tr == -1 else f', সর্বোচ্চ {max_tr}'}).")
            return
        st["tr"] = v
        st["n"] = "p_confirm"
        summary = (f"🧾 <b>নিশ্চিত করুন</b>\n\n🌍 Country: {esc(st['cc'] or 'any')}\n🔢 Quantity: {st['qty']}\n"
                   f"⏳ Session: {st['mins']} মিনিট\n📊 Traffic: {'Unlimited' if v == 0 else fmt_mb(v)}")
        await reply(update, summary, ikb([[("✅ তৈরি করুন", "p:ok"), ("❌ বাতিল", "p:no")]]))


async def do_create(update: Update, ctx: ContextTypes.DEFAULT_TYPE, st: dict) -> None:
    uid = update.effective_user.id
    qty, mins, tr, cc = st["qty"], st["mins"], st["tr"], st["cc"]
    adm = is_admin(uid)
    pkg = None
    reserved = False
    if not adm:
        c = await get_creator(uid)
        why = creator_problem(c)
        if why:
            await show(update, f"⛔ {why}")
            return
        pkg = await package_of(c)
        # অ্যাটমিক রিজার্ভেশন — কোটা পার হলে None
        res = await db.creators.find_one_and_update(
            {"_id": uid, "proxies_created": {"$lte": pkg["max_ip"] - qty},
             "traffic_allocated_mb": {"$lte": pkg["traffic_mb"] - tr}},
            {"$inc": {"proxies_created": qty, "traffic_allocated_mb": tr}})
        if not res:
            await show(update, "⛔ প্যাকেজের সীমা অতিক্রম করবে — তৈরি করা যায়নি।")
            return
        reserved = True

    await show(update, "⏳ Thordata-তে তৈরি হচ্ছে...")
    r, user, pw, last = None, "", "", ""
    for _ in range(3):
        user, pw = gen_username(), gen_password()
        r = await th.create_user(user, pw, tr, actor=uid)
        if r.ok:
            break
        last = f"{r.msg} (code {r.code})"
    if not r or not r.ok:
        if reserved:
            await db.creators.update_one({"_id": uid}, {"$inc": {"proxies_created": -qty, "traffic_allocated_mb": -tr}})
        await show(update, f"❌ <b>তৈরি ব্যর্থ</b>\n<code>{esc(last)}</code>")
        return

    lines = []
    for _ in range(qty):
        sid = "".join(secrets.choice(ALNUM) for _ in range(8))
        u = f"td-customer-{user}" + (f"-country-{cc}" if cc else "") + f"-sessid-{sid}-sesstime-{mins}"
        lines.append(f"{PROXY_HOST}:{PROXY_PORT}:{u}:{pw}")

    await db.proxies.insert_one({
        "ts": now(), "creator_id": uid, "is_admin": adm, "username": user,
        "password_enc": _fernet().encrypt(pw.encode()).decode(), "country": cc, "quantity": qty,
        "session_minutes": mins, "traffic_limit_mb": tr, "package_id": pkg["_id"] if pkg else None,
        "package_name": pkg["name"] if pkg else "ADMIN", "lines_count": len(lines)})
    await db.admin_logs.insert_one({"ts": now(), "admin_id": uid, "action": "create_proxy",
                                    "detail": f"user={user} qty={qty} cc={cc} mb={tr}"})
    head = (f"✅ <b>Proxy তৈরি সম্পন্ন</b>\n\n👤 Sub-user: <code>{esc(user)}</code>\n🔑 Password: <code>{esc(pw)}</code>\n"
            f"📊 Traffic: {'Unlimited' if tr == 0 else fmt_mb(tr)}\n🔢 লাইন: {qty} | ⏳ {mins} মিনিট\n"
            f"🌐 Host: <code>{esc(PROXY_HOST)}:{esc(PROXY_PORT)}</code>\n\nফরম্যাট: <code>host:port:user:pass</code>")
    preview = "\n".join(f"<code>{esc(x)}</code>" for x in lines[:5])
    more = f"\n… আরও {len(lines) - 5} টি ফাইলে।" if len(lines) > 5 else ""
    await show(update, f"{head}\n\n{preview}{more}")
    body = "\n".join(lines) + "\n\n# URL format\n" + "\n".join(
        f"http://{x.split(':', 2)[2].rsplit(':', 1)[0]}:{pw}@{PROXY_HOST}:{PROXY_PORT}" for x in lines)
    f = io.BytesIO(body.encode())
    f.name = f"proxies_{user}.txt"
    await update.effective_chat.send_document(f, caption="📎 সব Proxy লাইন")


# ──────────────────────────────── Packages ────────────────────────────────
PKG_FIELDS = {"name": "নাম", "traffic_mb": "Traffic Limit (MB)", "max_ip": "Max IP Quantity", "duration_days": "Duration (দিন, 0=মেয়াদহীন)"}


def package_text(p: dict) -> str:
    return (f"📦 <b>{esc(p['name'])}</b>\n📊 Traffic: {fmt_mb(p['traffic_mb'])}\n🔢 Max IP: {p['max_ip']}\n"
            f"⏳ মেয়াদ: {p['duration_days']} দিন" + (" (মেয়াদহীন)" if not p["duration_days"] else ""))


async def state_package_add(update: Update, ctx: ContextTypes.DEFAULT_TYPE, st: dict, text: str) -> None:
    step = st["step"]
    if step == "name":
        if not text or len(text) > 40:
            await reply(update, "❌ নাম ১–৪০ অক্ষরের মধ্যে দিন।")
            return
        st["name"], st["step"] = text, "traffic_mb"
        await reply(update, "📊 Traffic Limit (MB)? যেমন 10240 = 10 GB")
    elif step == "traffic_mb":
        v = to_int(text, MIN_TRAFFIC_MB, 10 ** 8)
        if v is None:
            await reply(update, f"❌ ন্যূনতম {MIN_TRAFFIC_MB} MB।")
            return
        st["traffic_mb"], st["step"] = v, "max_ip"
        await reply(update, "🔢 Maximum IP Quantity?")
    elif step == "max_ip":
        v = to_int(text, 1, 10 ** 6)
        if v is None:
            await reply(update, "❌ ১ বা তার বেশি সংখ্যা দিন।")
            return
        st["max_ip"], st["step"] = v, "duration_days"
        await reply(update, "⏳ প্যাকেজের মেয়াদ (দিন)? <code>0</code> = মেয়াদহীন")
    elif step == "duration_days":
        v = to_int(text, 0, 3650)
        if v is None:
            await reply(update, "❌ ০–৩৬৫০ এর মধ্যে দিন।")
            return
        doc = {"name": st["name"], "traffic_mb": st["traffic_mb"], "max_ip": st["max_ip"],
               "duration_days": v, "created_at": now()}
        res = await db.packages.insert_one(doc)
        await admin_log(update.effective_user.id, "package_add", st["name"])
        ctx.user_data.pop("st", None)
        await reply(update, "✅ প্যাকেজ তৈরি হয়েছে।\n\n" + package_text(doc),
                    ikb([[("📋 সব প্যাকেজ", "k:list")]]))


async def state_package_edit(update: Update, ctx: ContextTypes.DEFAULT_TYPE, st: dict, text: str) -> None:
    f, pid = st["field"], st["pid"]
    if f == "name":
        val = text[:40]
        ok = bool(val)
    elif f == "traffic_mb":
        val = to_int(text, MIN_TRAFFIC_MB, 10 ** 8)
        ok = val is not None
    elif f == "max_ip":
        val = to_int(text, 1, 10 ** 6)
        ok = val is not None
    else:
        val = to_int(text, 0, 3650)
        ok = val is not None
    if not ok:
        await reply(update, "❌ মান সঠিক নয়, আবার দিন।")
        return
    await db.packages.update_one({"_id": pid}, {"$set": {f: val}})
    await admin_log(update.effective_user.id, "package_edit", f"{pid} {f}={val}")
    ctx.user_data.pop("st", None)
    p = await db.packages.find_one({"_id": pid})
    await reply(update, "✅ আপডেট হয়েছে।\n\n" + package_text(p), ikb(package_buttons(p)))


def package_buttons(p: dict) -> list:
    pid = p["_id"]
    return [
        [("✏️ নাম", f"k:e:{pid}:name"), ("📊 Traffic", f"k:e:{pid}:traffic_mb")],
        [("🔢 Max IP", f"k:e:{pid}:max_ip"), ("⏳ Duration", f"k:e:{pid}:duration_days")],
        [("🗑️ Delete", f"k:d:{pid}")],
        [("⬅️ প্যাকেজ তালিকা", "k:list")],
    ]


async def cb_package(update: Update, ctx: ContextTypes.DEFAULT_TYPE, parts: list) -> None:
    uid = update.effective_user.id
    act = parts[1]
    if act == "menu":
        await show(update, "📦 <b>Package Management</b>",
                   ikb([[("➕ Add Package", "k:add")], [("📋 View All Packages", "k:list")], [("⬅️ Admin Panel", "a:menu")]]))
    elif act == "list":
        pkgs = await db.packages.find().to_list(100)
        rows = [[(f"📦 {p['name']} • {fmt_mb(p['traffic_mb'])} • {p['max_ip']} IP", f"k:v:{p['_id']}")] for p in pkgs]
        rows += [[("➕ Add Package", "k:add")], [("⬅️ Back", "k:menu")]]
        await show(update, f"📋 <b>প্যাকেজ তালিকা</b> ({len(pkgs)})", ikb(rows))
    elif act == "add":
        ctx.user_data["st"] = {"n": "k_add", "step": "name"}
        await show(update, "➕ নতুন প্যাকেজের <b>নাম</b> লিখুন। (বাতিল: /cancel)")
    elif act in ("v", "e", "d", "dy"):
        p = await db.packages.find_one({"_id": oid(parts[2])})
        if not p:
            await show(update, "❌ প্যাকেজ পাওয়া যায়নি।", ikb([[("⬅️ Back", "k:list")]]))
            return
        if act == "v":
            await show(update, package_text(p), ikb(package_buttons(p)))
        elif act == "e":
            field = parts[3]
            if field not in PKG_FIELDS:
                return
            ctx.user_data["st"] = {"n": "k_edit", "pid": p["_id"], "field": field}
            await show(update, f"✏️ নতুন <b>{PKG_FIELDS[field]}</b> লিখুন। (বাতিল: /cancel)")
        elif act == "d":
            cnt = await db.creators.count_documents({"package_id": p["_id"]})
            await show(update, f"⚠️ <b>{esc(p['name'])}</b> মুছবেন? এই প্যাকেজ {cnt} জন Creator-এর কাছে আছে — "
                               f"তাদের প্যাকেজ খালি হয়ে যাবে (ফলে Proxy তৈরি বন্ধ হবে)।",
                       ikb([[("✅ হ্যাঁ, মুছুন", f"k:dy:{p['_id']}"), ("❌ না", f"k:v:{p['_id']}")]]))
        else:
            await db.creators.update_many({"package_id": p["_id"]}, {"$set": {"package_id": None}})
            await db.packages.delete_one({"_id": p["_id"]})
            await admin_log(uid, "package_delete", p["name"])
            await show(update, "🗑️ প্যাকেজ মুছে ফেলা হয়েছে।", ikb([[("📋 তালিকা", "k:list")]]))


# ──────────────────────────────── Creators ────────────────────────────────
def creator_buttons(c: dict) -> list:
    u = c["_id"]
    return [
        [("📦 Assign Package", f"c:pk:{u}"), ("⏳ Set Expiry", f"c:exp:{u}")],
        [("📊 Usage", f"c:use:{u}"),
         ("✅ Unblock" if c.get("blocked") else "🚫 Block", f"c:blk:{u}")],
        [(("🔍 Balance চেক বন্ধ" if c.get("can_check_balance") else "🔍 Balance চেক চালু"), f"c:bal:{u}")],
        [("➖ Remove Creator", f"c:rm:{u}")],
        [("⬅️ তালিকা", "c:l:v:0")],
    ]


async def cb_creator(update: Update, ctx: ContextTypes.DEFAULT_TYPE, parts: list) -> None:
    uid = update.effective_user.id
    act = parts[1]
    if act == "menu":
        await show(update, "👥 <b>Creator Management</b>", ikb([
            [("➕ Create Creator", "c:add"), ("🔍 Search Creator", "c:search")],
            [("📋 View All Creators", "c:l:v:0")],
            [("⬅️ Admin Panel", "a:menu")]]))
    elif act == "add":
        ctx.user_data["st"] = {"n": "c_add_id"}
        await show(update, "➕ নতুন Creator-এর <b>Telegram User ID</b> লিখুন। (বাতিল: /cancel)")
    elif act == "search":
        ctx.user_data["st"] = {"n": "c_search"}
        await show(update, "🔍 Creator-এর নাম বা User ID লিখুন।")
    elif act == "l":
        mode, page = parts[2], int(parts[3])
        total = await db.creators.count_documents({})
        items = await db.creators.find().sort("created_at", -1).skip(page * 10).limit(10).to_list(10)
        rows = []
        for c in items:
            tag = "🚫" if c.get("blocked") else ("⏳" if c.get("expiry") and c["expiry"] < now() else "✅")
            rows.append([(f"{tag} {c.get('name') or c['_id']} ({c['_id']})", f"c:v:{c['_id']}")])
        nav = []
        if page > 0:
            nav.append(("⬅️", f"c:l:{mode}:{page - 1}"))
        if (page + 1) * 10 < total:
            nav.append(("➡️", f"c:l:{mode}:{page + 1}"))
        if nav:
            rows.append(nav)
        rows.append([("⬅️ Admin Panel", "a:menu")])
        title = "🗑️ <b>Delete/Disable Creator</b> — একজনকে বেছে নিন" if mode == "d" else "📋 <b>Creator List</b>"
        await show(update, f"{title}\nমোট: {total}" + ("" if items else "\n\nকোনো Creator নেই।"), ikb(rows))
    elif act == "addpk":
        st = ctx.user_data.get("st") or {}
        if st.get("n") != "c_add_pick":
            return
        cid, name = st["uid"], st["name"]
        pkg = None if parts[2] == "none" else await db.packages.find_one({"_id": oid(parts[2])})
        doc = {"_id": cid, "name": name, "package_id": pkg["_id"] if pkg else None,
               "expiry": (now() + timedelta(days=pkg["duration_days"])) if pkg and pkg["duration_days"] else None,
               "blocked": False, "can_check_balance": False, "proxies_created": 0,
               "traffic_allocated_mb": 0, "created_at": now(), "added_by": uid}
        await db.creators.insert_one(doc)
        await admin_log(uid, "creator_add", f"{cid}")
        ctx.user_data.pop("st", None)
        try:
            await ctx.bot.send_message(cid, "🎉 আপনাকে Creator Permission দেওয়া হয়েছে। /start দিন।")
        except Exception:
            pass
        await show(update, "✅ Creator তৈরি হয়েছে।\n\n" + await creator_text(doc), ikb(creator_buttons(doc)))
    else:
        cid = int(parts[2])
        c = await get_creator(cid)
        if not c:
            await show(update, "❌ Creator পাওয়া যায়নি।", ikb([[("⬅️ Back", "c:l:v:0")]]))
            return
        if act == "v":
            await show(update, await creator_text(c), ikb(creator_buttons(c)))
        elif act == "pk":
            pkgs = await db.packages.find().to_list(50)
            rows = [[(f"📦 {p['name']}", f"c:pks:{cid}:{p['_id']}")] for p in pkgs] or []
            rows.append([("⬅️ Back", f"c:v:{cid}")])
            await show(update, "📦 প্যাকেজ বেছে নিন।\n<i>নতুন প্যাকেজ দিলে Creator-এর ব্যবহার (IP/Traffic) শূন্য থেকে শুরু হবে এবং মেয়াদ প্যাকেজ অনুযায়ী সেট হবে।</i>"
                       + ("" if pkgs else "\n\n⚠️ কোনো প্যাকেজ নেই — আগে প্যাকেজ তৈরি করুন।"), ikb(rows))
        elif act == "pks":
            p = await db.packages.find_one({"_id": oid(parts[3])})
            if p:
                exp = now() + timedelta(days=p["duration_days"]) if p["duration_days"] else None
                await db.creators.update_one({"_id": cid}, {"$set": {"package_id": p["_id"], "expiry": exp,
                                                                     "proxies_created": 0, "traffic_allocated_mb": 0}})
                await admin_log(uid, "assign_package", f"creator={cid} package={p['name']}")
            c = await get_creator(cid)
            await show(update, "✅ প্যাকেজ অ্যাসাইন হয়েছে।\n\n" + await creator_text(c), ikb(creator_buttons(c)))
        elif act == "exp":
            ctx.user_data["st"] = {"n": "c_exp", "uid": cid}
            await show(update, "⏳ আজ থেকে কত <b>দিন</b> মেয়াদ? (<code>0</code> = মেয়াদহীন)")
        elif act == "blk":
            nb = not c.get("blocked")
            await db.creators.update_one({"_id": cid}, {"$set": {"blocked": nb}})
            await admin_log(uid, "block" if nb else "unblock", str(cid))
            c = await get_creator(cid)
            await show(update, await creator_text(c), ikb(creator_buttons(c)))
        elif act == "bal":
            await db.creators.update_one({"_id": cid}, {"$set": {"can_check_balance": not c.get("can_check_balance")}})
            await admin_log(uid, "toggle_balance_perm", str(cid))
            c = await get_creator(cid)
            await show(update, await creator_text(c), ikb(creator_buttons(c)))
        elif act == "use":
            recent = await db.proxies.find({"creator_id": cid}).sort("ts", -1).limit(10).to_list(10)
            tot = await db.proxies.count_documents({"creator_id": cid})
            lines = [await creator_text(c, short=True), "", f"🧾 মোট তৈরি (sub-user): {tot}", "<b>সর্বশেষ ১০টি:</b>"]
            for x in recent:
                lines.append(f"• {x['ts'].strftime('%m-%d %H:%M')} | <code>{esc(x['username'])}</code> | "
                             f"{x['quantity']} IP | {fmt_mb(x['traffic_limit_mb']) if x['traffic_limit_mb'] else 'Unlimited'}")
            await show(update, "\n".join(lines), ikb([[("⬅️ Back", f"c:v:{cid}")]]))
        elif act == "rm":
            await show(update, f"⚠️ <b>{esc(c.get('name') or cid)}</b> এর Creator Permission তুলে নেবেন? "
                               f"(তৈরি করা Proxy রেকর্ড থাকবে।)",
                       ikb([[("✅ হ্যাঁ", f"c:rmy:{cid}"), ("❌ না", f"c:v:{cid}")]]))
        elif act == "rmy":
            await db.creators.delete_one({"_id": cid})
            await admin_log(uid, "creator_remove", str(cid))
            await show(update, "➖ Creator Permission সরানো হয়েছে।", ikb([[("📋 তালিকা", "c:l:v:0")]]))


# ──────────────────────────────── Admin callbacks ────────────────────────────────
async def usage_report_text() -> str:
    total_cr = await db.creators.count_documents({})
    active = await db.creators.count_documents({"blocked": {"$ne": True},
                                                "$or": [{"expiry": None}, {"expiry": {"$gt": now()}}]})
    tot = await db.proxies.aggregate([{"$group": {"_id": None, "subs": {"$sum": 1}, "ips": {"$sum": "$quantity"},
                                                  "mb": {"$sum": "$traffic_limit_mb"}}}]).to_list(1)
    tot = tot[0] if tot else {"subs": 0, "ips": 0, "mb": 0}
    per_cr = await db.proxies.aggregate([{"$group": {"_id": "$creator_id", "n": {"$sum": 1}, "ips": {"$sum": "$quantity"}}},
                                         {"$sort": {"ips": -1}}, {"$limit": 8}]).to_list(8)
    per_pk = await db.proxies.aggregate([{"$group": {"_id": "$package_name", "n": {"$sum": 1}, "ips": {"$sum": "$quantity"},
                                                     "mb": {"$sum": "$traffic_limit_mb"}}},
                                         {"$sort": {"ips": -1}}, {"$limit": 8}]).to_list(8)
    api_total = await db.api_logs.count_documents({})
    api_ok = await db.api_logs.count_documents({"ok": True})
    since = now() - timedelta(hours=24)
    api_24 = await db.api_logs.count_documents({"ts": {"$gte": since}})
    api_24_fail = await db.api_logs.count_documents({"ts": {"$gte": since}, "ok": False})
    fails = await db.api_logs.find({"ok": False}).sort("ts", -1).limit(3).to_list(3)
    out = ["📈 <b>Usage Report</b> <i>(বটের নিজস্ব রেকর্ড)</i>", "",
           f"👥 মোট Creator: {total_cr} | সক্রিয়: {active}",
           f"🌐 মোট তৈরি: {tot['subs']} sub-user / {tot['ips']} IP লাইন",
           f"📊 মোট বরাদ্দ Traffic: {fmt_mb(tot['mb'])}", "", "<b>Creator অনুযায়ী (top):</b>"]
    for x in per_cr:
        c = await get_creator(x["_id"]) if x["_id"] not in ADMIN_IDS else None
        label = "👑 Admin" if x["_id"] in ADMIN_IDS else (c.get("name") if c and c.get("name") else x["_id"])
        out.append(f"• {esc(label)}: {x['n']} user / {x['ips']} IP")
    out += ["", "<b>Package অনুযায়ী:</b>"]
    for x in per_pk:
        out.append(f"• {esc(x['_id'])}: {x['n']} user / {x['ips']} IP / {fmt_mb(x['mb'])}")
    out += ["", f"🔌 API Request: মোট {api_total} (সফল {api_ok}, ব্যর্থ {api_total - api_ok})",
            f"🕒 গত ২৪ ঘণ্টা: {api_24} (ব্যর্থ {api_24_fail})"]
    if fails:
        out.append("<b>সাম্প্রতিক ব্যর্থতা:</b>")
        for f in fails:
            out.append(f"• {f['ts'].strftime('%m-%d %H:%M')} {esc(f['action'])}: {esc(f['msg'][:60])}")
    return "\n".join(out)


async def cb_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE, parts: list) -> None:
    uid = update.effective_user.id
    act = parts[1]
    back = ikb([[("⬅️ Admin Panel", "a:menu")]])
    if act == "menu":
        await send_admin_panel(update)
    elif act == "tok":
        token, key = await th.creds()
        src = "Database (এনক্রিপ্টেড)" if await get_setting("api_token") else ("Environment (.env)" if token else "—")
        await show(update, f"🔑 <b>API Token Settings</b>\n\nToken: {'✅ সেট আছে' if token else '❌ নেই'}\n"
                           f"Key: {'✅ সেট আছে' if key else '— নেই'}\nসোর্স: {src}\n\n<i>Token কখনো দেখানো হয় না।</i>",
                   ikb([[("🔁 Set/Change Token", "a:toks")], [("🧪 Test Connection", "a:tokt")],
                        [("⬅️ Admin Panel", "a:menu")]]))
    elif act == "toks":
        ctx.user_data["st"] = {"n": "tok_set"}
        await show(update, "🔐 Thordata <b>Public Token</b> পাঠান (Dashboard → My Account)।\n"
                           "<i>বার্তাটি পাঠানোর পরই মুছে ফেলা হবে।</i> বাতিল: /cancel")
    elif act == "tokt":
        await show(update, "🧪 টেস্ট হচ্ছে...")
        await show(update, await test_connection_text(uid), ikb([[("⬅️ Back", "a:tok")]]))
    elif act == "cbal":
        ctx.user_data["st"] = {"n": "cbal"}
        await show(update, "🔎 যেকোনো <b>Proxy Username</b> লিখে পাঠান। (বাতিল: /cancel)")
    elif act == "web":
        await show(update, "⏳ তথ্য আনা হচ্ছে...")
        await show(update, await web_balance_text(uid), ikb([[("🔄 Refresh", "a:web")], [("⬅️ Admin Panel", "a:menu")]]))
    elif act == "rep":
        await show(update, await usage_report_text(), ikb([[("🔄 Refresh", "a:rep")], [("⬅️ Admin Panel", "a:menu")]]))
    elif act == "sup":
        txt = await get_setting("support_text", "— সেট করা নেই —")
        await show(update, f"🆘 <b>Support Settings</b>\n\nবর্তমান:\n{esc(txt)}",
                   ikb([[("✏️ পরিবর্তন করুন", "a:supe")], [("⬅️ Admin Panel", "a:menu")]]))
    elif act == "supe":
        ctx.user_data["st"] = {"n": "sup_edit"}
        await show(update, "✏️ নতুন Support তথ্য (যোগাযোগের নাম/লিংক/নম্বর) লিখুন। (বাতিল: /cancel)")
    elif act == "set":
        m = await get_setting("maintenance", False)
        q = await get_setting("max_qty", 50)
        s = await get_setting("max_session", 120)
        await show(update, "⚙️ <b>Bot Settings</b>\n\n"
                           f"🛠️ Maintenance: {'ON' if m else 'OFF'}\n🔢 এক রিকোয়েস্টে সর্বোচ্চ Quantity: {q}\n"
                           f"⏳ সর্বোচ্চ Session মিনিট: {s}\n"
                           f"🔌 Proxy host: <code>{esc(PROXY_HOST)}:{esc(PROXY_PORT)}</code> (.env)\n\n"
                           "<i>Package expiry/quota বটের নিজস্ব নিয়ম; Thordata-তে কার্যকর হয় শুধু sub-user traffic_limit।</i>",
                   ikb([[(f"🛠️ Maintenance {'বন্ধ' if m else 'চালু'} করুন", "a:setm")],
                        [("🔢 Max Quantity", "a:setv:max_qty"), ("⏳ Max Session", "a:setv:max_session")],
                        [("⬅️ Admin Panel", "a:menu")]]))
    elif act == "setm":
        m = not await get_setting("maintenance", False)
        await set_setting("maintenance", m)
        await admin_log(uid, "maintenance", str(m))
        await cb_admin(update, ctx, ["a", "set"])
    elif act == "setv":
        ctx.user_data["st"] = {"n": "set_val", "key": parts[2]}
        await show(update, "নতুন মান (সংখ্যা) লিখুন। (বাতিল: /cancel)")


async def on_cb(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    uid = q.from_user.id
    parts = (q.data or "").split(":")
    try:
        await q.answer()
        ns = parts[0]
        if ns in ("a", "k", "c"):
            if not is_admin(uid):  # Unauthorized কেউ Admin ফাংশন চালাতে পারবে না
                await log_unauth(uid, q.data)
                return
            if ns == "a":
                await cb_admin(update, ctx, parts)
            elif ns == "k":
                await cb_package(update, ctx, parts)
            else:
                await cb_creator(update, ctx, parts)
        elif ns == "p":
            if parts[1] == "new":
                await start_create(update, ctx)
            elif parts[1] == "ok":
                st = ctx.user_data.get("st")
                if st and st.get("n") == "p_confirm":
                    ctx.user_data.pop("st", None)
                    await do_create(update, ctx, st)
            elif parts[1] == "no":
                ctx.user_data.pop("st", None)
                await show(update, "❎ বাতিল করা হয়েছে।")
    except Exception:
        log.exception("callback error: %s", q.data)
        try:
            await ctx.bot.send_message(uid, "⚠️ একটি অভ্যন্তরীণ ত্রুটি হয়েছে। আবার চেষ্টা করুন।")
        except Exception:
            pass


async def log_unauth(uid: int, data: str) -> None:
    log.warning("UNAUTHORIZED admin callback uid=%s data=%s", uid, data)
    await db.admin_logs.insert_one({"ts": now(), "admin_id": uid, "action": "UNAUTHORIZED", "detail": data})


async def on_error(update: object, ctx: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled exception", exc_info=ctx.error)


# ──────────────────────────────── Startup ────────────────────────────────
def start_health_server() -> None:
    """Render/Koyeb ইত্যাদি ফ্রি হোস্টিংয়ের জন্য ছোট health-check সার্ভার (PORT থাকলে)।"""
    port = int(os.getenv("PORT", "0") or 0)
    if not port:
        return

    class H(BaseHTTPRequestHandler):
        def _ok(self):
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            self._ok()
            self.wfile.write(b"ok")

        def do_HEAD(self):
            self._ok()

        def log_message(self, *a):
            pass

    threading.Thread(target=HTTPServer(("0.0.0.0", port), H).serve_forever, daemon=True).start()
    log.info("Health server port %s এ চালু", port)


async def post_init(app: Application) -> None:
    global db, th
    client = AsyncIOMotorClient(MONGO_URI, tz_aware=True, serverSelectionTimeoutMS=15000)
    await client.admin.command("ping")
    db = client[MONGO_DB]
    th = Thordata()
    await db.api_logs.create_index("ts")
    await db.proxies.create_index("creator_id")
    await db.admin_logs.create_index("ts")
    _fernet()  # কী ঠিক আছে কিনা এখনই যাচাই
    log.info("MongoDB সংযুক্ত। Admins: %s", sorted(ADMIN_IDS))


async def post_shutdown(app: Application) -> None:
    if th:
        await th.http.aclose()


def main() -> None:
    missing = [k for k, v in {"BOT_TOKEN": BOT_TOKEN, "MONGO_URI": MONGO_URI, "ADMIN_IDS": ADMIN_IDS}.items() if not v]
    if missing:
        sys.exit(f"❌ .env-এ এগুলো সেট করুন: {', '.join(missing)}")
    start_health_server()
    app = Application.builder().token(BOT_TOKEN).post_init(post_init).post_shutdown(post_shutdown).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CommandHandler("panel", cmd_panel))
    app.add_handler(CallbackQueryHandler(on_cb))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)
    log.info("Bot polling শুরু...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
