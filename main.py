"""
Telegram Phone Verification (OTP) Bot — Twilio Verify

- ইউজার শুধু ফোন নম্বর দেয় (SMS টেক্সট লেখার অপশন নেই)।
- OTP পাঠায় Twilio Verify (অনুমোদিত, বাস্তব provider)।
- কোনো ডেমো/ফেক মোড নেই। Credentials না থাকলে বট চালুই হবে না।
- কোনো অটো-পেমেন্ট নেই: বট কখনো অ্যাকাউন্ট আপগ্রেড/টপ-আপ করে না।
- Free credit শেষ হলে (লোকাল গণনা বা Twilio-র এরর) ইউজার ও অ্যাডমিনকে জানায়।

গুরুত্বপূর্ণ: Twilio ট্রায়ালে শুধু "Verified" নম্বরে (সর্বোচ্চ ৫টি) কোড পাঠানো যায়।
অজানা আন্তর্জাতিক নম্বরে পাঠাতে হলে Twilio অ্যাকাউন্ট আপগ্রেড (paid) লাগবে।
"""

import asyncio
import hashlib
import logging
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import phonenumbers
from dotenv import load_dotenv
from telegram import KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove, Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
from twilio.base.exceptions import TwilioException, TwilioRestException
from twilio.rest import Client

load_dotenv()
logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
log = logging.getLogger("otpbot")


# ----------------------------- Config -----------------------------
def env(name, default=None, required=False):
    v = os.getenv(name, default)
    if required and not v:
        raise SystemExit(f"❌ {name} সেট করা নেই (.env দেখুন)।")
    return v


def env_int(name, default):
    return int(os.getenv(name, default))


def env_ids(name):
    return {int(x) for x in os.getenv(name, "").replace(" ", "").split(",") if x}


BOT_TOKEN = env("TELEGRAM_BOT_TOKEN", required=True)
TWILIO_SID = env("TWILIO_ACCOUNT_SID", required=True)
TWILIO_TOKEN = env("TWILIO_AUTH_TOKEN", required=True)
VERIFY_SID = env("TWILIO_VERIFY_SERVICE_SID", required=True)

ADMIN_IDS = env_ids("ADMIN_IDS")
ALLOWED_USER_IDS = env_ids("ALLOWED_USER_IDS")  # খালি = সবাই
ALLOWED_COUNTRIES = {c.strip().upper() for c in env("ALLOWED_COUNTRIES", "").split(",") if c.strip()}
REQUIRE_CONTACT_SHARE = env("REQUIRE_CONTACT_SHARE", "false").lower() == "true"

FREE_SEND_LIMIT = env_int("FREE_SEND_LIMIT", 40)    # Twilio Verify trial: 40 free verifications
DAILY_SEND_CAP = env_int("DAILY_SEND_CAP", 20)      # সব ইউজার মিলিয়ে দৈনিক সীমা
USER_HOURLY_LIMIT = env_int("USER_HOURLY_LIMIT", 3)
USER_DAILY_LIMIT = env_int("USER_DAILY_LIMIT", 5)
PHONE_DAILY_LIMIT = env_int("PHONE_DAILY_LIMIT", 3)
RESEND_COOLDOWN = env_int("RESEND_COOLDOWN", 60)
MAX_CODE_ATTEMPTS = env_int("MAX_CODE_ATTEMPTS", 5)
CODE_TTL = env_int("CODE_TTL", 600)
CHANNEL = env("OTP_CHANNEL", "sms")
HASH_SALT = env("HASH_SALT", "change-me")
DB_PATH = env("DB_PATH", "otpbot.db")

twilio = Client(TWILIO_SID, TWILIO_TOKEN)

# ----------------------------- Storage -----------------------------
_db_lock = threading.Lock()
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS events (kind TEXT, user_id INTEGER, phone_hash TEXT, ts REAL)")
db.execute("CREATE INDEX IF NOT EXISTS ix_events ON events(kind, ts)")
db.commit()


def phone_hash(e164):
    # ফোন নম্বর প্লেইন টেক্সটে সেভ করা হয় না — শুধু salted hash।
    return hashlib.sha256((HASH_SALT + e164).encode()).hexdigest()


def record(kind, user_id, phone=None):
    with _db_lock:
        db.execute("INSERT INTO events VALUES (?,?,?,?)",
                   (kind, user_id, phone_hash(phone) if phone else None, time.time()))
        db.commit()


def count(kind, since=0.0, user_id=None, phone=None):
    q, a = "SELECT COUNT(*) FROM events WHERE kind=? AND ts>=?", [kind, since]
    if user_id is not None:
        q += " AND user_id=?"; a.append(user_id)
    if phone is not None:
        q += " AND phone_hash=?"; a.append(phone_hash(phone))
    with _db_lock:
        return db.execute(q, a).fetchone()[0]


def last_ts(kind, user_id):
    with _db_lock:
        r = db.execute("SELECT MAX(ts) FROM events WHERE kind=? AND user_id=?", (kind, user_id)).fetchone()
    return r[0] or 0.0


# ----------------------------- Twilio (blocking → thread) -----------------------------
def tw_send(e164):
    return twilio.verify.v2.services(VERIFY_SID).verifications.create(to=e164, channel=CHANNEL)


def tw_check(e164, code):
    return twilio.verify.v2.services(VERIFY_SID).verification_checks.create(to=e164, code=code)


CREDIT_HINTS = ("balance", "insufficient", "funds", "free units", "exceeded", "trial", "upgrade")


def classify_twilio_error(e: TwilioRestException):
    """(user_message, is_credit_problem) — Twilio এরর কোড/মেসেজ থেকে অনুমান।"""
    msg = (e.msg or "").lower()
    if e.status == 402 or any(h in msg for h in ("balance", "insufficient", "free units")):
        return ("⚠️ Free credit/ব্যালেন্স শেষ। বট স্বয়ংক্রিয়ভাবে টাকা খরচ করে না। "
                "অ্যাডমিন Twilio অ্যাকাউন্ট রিচার্জ/আপগ্রেড করলে আবার চলবে।"), True
    if e.code == 60203:
        return "⛔ এই নম্বরে সর্বোচ্চ সংখ্যক কোড পাঠানো হয়েছে। কিছুক্ষণ পরে চেষ্টা করুন।", False
    if e.code in (60200, 60205) or "invalid parameter" in msg:
        return "❌ এই নম্বরে SMS পাঠানো সম্ভব নয় (অবৈধ/অসমর্থিত নম্বর)।", False
    if "unverified" in msg or "verified" in msg or "trial" in msg:
        return ("🔒 Twilio ট্রায়াল মোডে শুধু Twilio-তে Verified করা নম্বরে কোড যায়। "
                "এই নম্বর অ্যাডমিন Verified Caller IDs-এ যোগ করেননি।"), False
    if e.status == 429:
        return "⏳ সার্ভার ব্যস্ত। একটু পরে চেষ্টা করুন।", False
    return "❌ কোড পাঠানো যায়নি। পরে আবার চেষ্টা করুন।", False


async def notify_admins(app, text):
    for aid in ADMIN_IDS:
        try:
            await app.bot.send_message(aid, text)
        except Exception:
            log.exception("admin notify failed")


# ----------------------------- Handlers -----------------------------
def phone_keyboard():
    rows = [[KeyboardButton("📱 আমার নম্বর শেয়ার করুন", request_contact=True)]]
    return ReplyKeyboardMarkup(rows, resize_keyboard=True, one_time_keyboard=True)


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    ctx.user_data["state"] = "phone"
    if REQUIRE_CONTACT_SHARE:
        text = "স্বাগতম! নিচের বাটনে চাপ দিয়ে আপনার নম্বর শেয়ার করুন।"
    else:
        text = ("স্বাগতম! আপনার ফোন নম্বর দিন কান্ট্রি কোডসহ।\nউদাহরণ: +8801XXXXXXXXX, +14155550123\n"
                "অথবা নিচের বাটনে নম্বর শেয়ার করুন।")
    await update.message.reply_text(text, reply_markup=phone_keyboard())


async def cmd_cancel(update, ctx):
    ctx.user_data.clear()
    await update.message.reply_text("বাতিল করা হয়েছে। /start দিয়ে আবার শুরু করুন।", reply_markup=ReplyKeyboardRemove())


async def cmd_help(update, ctx):
    await update.message.reply_text("/start — ভেরিফিকেশন শুরু\n/cancel — বাতিল\n"
                                    "আপনি শুধু ফোন নম্বর দেবেন; কোড SMS-এ আসবে, সেই কোড এখানে লিখবেন।")


async def cmd_status(update, ctx):
    if update.effective_user.id not in ADMIN_IDS:
        return
    used = count("send")
    today = count("send", time.time() - 86400)
    await update.message.reply_text(
        f"মোট পাঠানো (লোকাল গণনা): {used}/{FREE_SEND_LIMIT}\nগত ২৪ ঘণ্টা: {today}/{DAILY_SEND_CAP}\n"
        "প্রকৃত ব্যালেন্স দেখুন: Twilio Console → Free units tracker।")


def parse_phone(raw):
    try:
        num = phonenumbers.parse(raw, None)  # +country code বাধ্যতামূলক
    except phonenumbers.NumberParseException:
        return None, "❌ নম্বরটি + এবং কান্ট্রি কোডসহ দিন (যেমন +8801XXXXXXXXX)।"
    if not phonenumbers.is_valid_number(num):
        return None, "❌ নম্বরটি বৈধ নয়।"
    region = phonenumbers.region_code_for_number(num)
    if ALLOWED_COUNTRIES and region not in ALLOWED_COUNTRIES:
        return None, "🌍 এই দেশ বর্তমানে সমর্থিত নয়।"
    return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164), None


async def handle_phone(update, ctx, raw):
    user = update.effective_user
    e164, err = parse_phone(raw)
    if err:
        return await update.message.reply_text(err)

    now = time.time()
    # --- Free credit / budget guard (লোকাল) ---
    if count("send") >= FREE_SEND_LIMIT:
        await notify_admins(ctx.application, "⚠️ Free verification limit শেষ। রিচার্জ না করলে বট কোড পাঠাবে না।")
        return await update.message.reply_text(
            "⚠️ Free credit শেষ। বট স্বয়ংক্রিয়ভাবে টাকা খরচ করে না। অ্যাডমিনকে জানানো হয়েছে।")
    if count("send", now - 86400) >= DAILY_SEND_CAP:
        return await update.message.reply_text("⏳ আজকের সর্বোচ্চ সীমা শেষ। আগামীকাল চেষ্টা করুন।")
    # --- Spam protection ---
    wait = RESEND_COOLDOWN - (now - last_ts("send", user.id))
    if wait > 0:
        return await update.message.reply_text(f"⏳ {int(wait)+1} সেকেন্ড পরে আবার চেষ্টা করুন।")
    if count("send", now - 3600, user_id=user.id) >= USER_HOURLY_LIMIT:
        return await update.message.reply_text("⛔ ঘণ্টায় সর্বোচ্চ সীমা পার হয়েছে।")
    if count("send", now - 86400, user_id=user.id) >= USER_DAILY_LIMIT:
        return await update.message.reply_text("⛔ দৈনিক সীমা পার হয়েছে।")
    if count("send", now - 86400, phone=e164) >= PHONE_DAILY_LIMIT:
        return await update.message.reply_text("⛔ এই নম্বরে আজ আর কোড পাঠানো যাবে না।")

    try:
        v = await asyncio.to_thread(tw_send, e164)
    except TwilioRestException as e:
        log.warning("twilio send error %s %s", e.code, e.msg)
        msg, credit = classify_twilio_error(e)
        if credit:
            await notify_admins(ctx.application, f"⚠️ Twilio credit সমস্যা: {e.code} {e.msg}")
        return await update.message.reply_text(msg)
    except TwilioException:
        log.exception("twilio failure")
        return await update.message.reply_text("❌ সার্ভিস সাময়িক অনুপলব্ধ। পরে চেষ্টা করুন।")

    record("send", user.id, e164)
    ctx.user_data.update(state="code", phone=e164, attempts=0, sent_at=now)
    log.info("verification sent status=%s user=%s", v.status, user.id)
    await update.message.reply_text(
        f"✅ কোড পাঠানো হয়েছে ({CHANNEL.upper()}). ৪–১০ ডিজিটের কোডটি এখানে লিখুন।\n"
        f"মেয়াদ প্রায় {CODE_TTL // 60} মিনিট। বাতিল: /cancel",
        reply_markup=ReplyKeyboardRemove())


async def handle_code(update, ctx, raw):
    user = update.effective_user
    code = raw.replace(" ", "")
    if time.time() - ctx.user_data.get("sent_at", 0) > CODE_TTL:
        ctx.user_data.clear()
        return await update.message.reply_text("⌛ কোডের মেয়াদ শেষ। /start দিয়ে আবার শুরু করুন।")
    if not (code.isdigit() and 4 <= len(code) <= 10):
        return await update.message.reply_text("❌ শুধু সংখ্যার কোড লিখুন।")
    ctx.user_data["attempts"] += 1
    if ctx.user_data["attempts"] > MAX_CODE_ATTEMPTS:
        ctx.user_data.clear()
        return await update.message.reply_text("⛔ অনেকবার ভুল। /start দিয়ে নতুন কোড নিন।")
    try:
        r = await asyncio.to_thread(tw_check, ctx.user_data["phone"], code)
    except TwilioRestException as e:
        log.warning("twilio check error %s %s", e.code, e.msg)
        if e.status == 404 or e.code in (20404, 60202):
            ctx.user_data.clear()
            return await update.message.reply_text("⌛ কোড মেয়াদোত্তীর্ণ বা অতিরিক্ত চেষ্টা। /start দিন।")
        return await update.message.reply_text("❌ যাচাই করা যায়নি। পরে চেষ্টা করুন।")
    try:  # নিরাপত্তার জন্য কোডের মেসেজ মুছে ফেলার চেষ্টা
        await update.message.delete()
    except Exception:
        pass
    if r.status == "approved":
        phone = ctx.user_data["phone"]
        record("verified", user.id, phone)
        ctx.user_data.clear()
        # TODO: এখানে আপনার নিজের লজিক বসান (যেমন DB-তে verified flag সেট করা)
        await ctx.bot.send_message(user.id, "🎉 ফোন নম্বর সফলভাবে ভেরিফাই হয়েছে!")
    else:
        left = MAX_CODE_ATTEMPTS - ctx.user_data["attempts"]
        await ctx.bot.send_message(user.id, f"❌ ভুল কোড। আর {left}বার চেষ্টা করতে পারবেন।")


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if ALLOWED_USER_IDS and user.id not in ALLOWED_USER_IDS:
        return await update.message.reply_text("⛔ আপনি এই বট ব্যবহারের অনুমতিপ্রাপ্ত নন।")
    text = (update.message.text or "").strip()
    state = ctx.user_data.get("state")
    if state == "code":
        return await handle_code(update, ctx, text)
    if REQUIRE_CONTACT_SHARE:
        return await update.message.reply_text("📱 অনুগ্রহ করে বাটন ব্যবহার করে নম্বর শেয়ার করুন (/start)।")
    if state == "phone":
        return await handle_phone(update, ctx, text)
    await update.message.reply_text("শুরু করতে /start দিন।")


async def on_contact(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user, c = update.effective_user, update.message.contact
    if ALLOWED_USER_IDS and user.id not in ALLOWED_USER_IDS:
        return await update.message.reply_text("⛔ অনুমতি নেই।")
    if c.user_id != user.id:  # অন্য কারো কন্টাক্ট নয়
        return await update.message.reply_text("❌ শুধু নিজের নম্বর শেয়ার করুন।")
    raw = c.phone_number if c.phone_number.startswith("+") else "+" + c.phone_number
    await handle_phone(update, ctx, raw)


# ----------------------------- Optional health server (free hosts) -----------------------------
def start_health_server():
    port = os.getenv("PORT")
    if not port:
        return

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    threading.Thread(target=HTTPServer(("0.0.0.0", int(port)), H).serve_forever, daemon=True).start()


def main():
    start_health_server()
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(MessageHandler(filters.CONTACT, on_contact))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    log.info("Bot started (Twilio Verify, channel=%s)", CHANNEL)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
