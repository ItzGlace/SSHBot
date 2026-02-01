#!/usr/bin/env python3
import os
import sys
import time
import threading
import logging
import logging.handlers
import re
from typing import Dict, Tuple, List

import paramiko
import pyte

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ParseMode,
)
from telegram.ext import (
    Updater,
    CommandHandler,
    MessageHandler,
    Filters,
    CallbackQueryHandler,
    CallbackContext,
)

# ================= CONFIG =================
BOT_TOKEN = os.environ.get("BOT_TOKEN")
TERM_COLS = 120
TERM_LINES = 200
UPDATE_INTERVAL = 1.0
MAX_TG_CHARS = 3900

LOG_DIR = "/var/log/ssh-bot"
LOG_FILE = f"{LOG_DIR}/ssh-bot.log"

REPO_URL = "https://github.com/ItzGlace/SSHBot"

# ================= LOGGING =================
os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger("ssh-bot")
logger.setLevel(logging.INFO)

fmt = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
fh.setFormatter(fmt)
logger.addHandler(fh)

sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(fmt)
logger.addHandler(sh)

# ================= STATE =================
SESSIONS: Dict[int, "SSHSession"] = {}
PENDING: Dict[int, Tuple[str, str, int]] = {}

SSH_RE = re.compile(r"([^@]+)@([^:]+)(?::(\d+))?$")

KEYS = {
    "TAB": "\t",
    "ENTER": "\r",
    "ESC": "\x1b",
    "BS": "\x7f",
    "UP": "\x1b[A",
    "DOWN": "\x1b[B",
    "LEFT": "\x1b[D",
    "RIGHT": "\x1b[C",
    "PGUP": "\x1b[5~",
    "PGDN": "\x1b[6~",
    "NANO_EXIT": "\x18",  # CTRL+X
}

# ================= SSH SESSION =================
class SSHSession:
    def __init__(self, chat_id: int, bot):
        self.chat_id = chat_id
        self.bot = bot

        self.client = None
        self.chan = None
        self.stop = threading.Event()
        self.thread = None

        self.screen = pyte.Screen(TERM_COLS, TERM_LINES)
        self.stream = pyte.Stream(self.screen)

        self.message_id = None
        self.last_render = ""
        self.last_sent = ""

    # ---------- CONNECT ----------
    def start(self, user, host, port, password):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                host,
                port=port,
                username=user,
                password=password,
                look_for_keys=False,
                allow_agent=False,
                timeout=10,
            )

            self.chan = self.client.invoke_shell()
            self.chan.settimeout(0)

            msg = self.bot.send_message(
                self.chat_id,
                text="```Connecting...```",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=self.keyboard(),
            )
            self.message_id = msg.message_id

            self.thread = threading.Thread(target=self.loop, daemon=True)
            self.thread.start()
            return True, None

        except Exception as e:
            logger.exception("SSH connect failed")
            return False, str(e)

    # ---------- LOOP ----------
    def loop(self):
        last_update = 0
        while not self.stop.is_set():
            try:
                if self.chan and self.chan.recv_ready():
                    data = self.chan.recv(4096)
                    if not data:
                        break
                    self.stream.feed(data.decode(errors="replace"))

                now = time.time()
                if now - last_update >= UPDATE_INTERVAL:
                    self.render_and_update()
                    last_update = now

                time.sleep(0.05)
            except Exception:
                logger.exception("Reader loop error")
                break

        # ensure close is called
        try:
            self.close()
        except Exception:
            pass

    # ---------- RENDER ----------
    def render_and_update(self):
        text = "\n".join(self.screen.display).rstrip()

        if text == self.last_render:
            return

        self.last_render = text
        safe = self.clamp(text)

        if safe == self.last_sent:
            return

        try:
            self.bot.edit_message_text(
                chat_id=self.chat_id,
                message_id=self.message_id,
                text=f"```{safe}```",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=self.keyboard(),
            )
            self.last_sent = safe
        except Exception as e:
            logger.warning("Edit failed: %s", e)

    # ---------- CLAMP ----------
    def clamp(self, text: str) -> str:
        lines = text.splitlines()
        out = []
        for line in reversed(lines):
            out.insert(0, line)
            if len("\n".join(out)) > MAX_TG_CHARS:
                out.pop(0)
                break
        return "\n".join(out)

    # ---------- INPUT ----------
    def send(self, text: str):
        try:
            if self.chan and not self.stop.is_set():
                self.chan.send(text)
        except Exception:
            logger.exception("Send failed")

    # ---------- KEYBOARD (no mod toggles) ----------
    def keyboard(self):
        # removed CTRL/ALT/SHIFT buttons per request
        return InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("TAB", callback_data="K:TAB"),
                    InlineKeyboardButton("ENTER", callback_data="K:ENTER"),
                    InlineKeyboardButton("ESC", callback_data="K:ESC"),
                    InlineKeyboardButton("BS", callback_data="K:BS"),
                ],
                [
                    InlineKeyboardButton("↑", callback_data="K:UP"),
                    InlineKeyboardButton("↓", callback_data="K:DOWN"),
                    InlineKeyboardButton("←", callback_data="K:LEFT"),
                    InlineKeyboardButton("→", callback_data="K:RIGHT"),
                ],
                [
                    InlineKeyboardButton("PGUP", callback_data="K:PGUP"),
                    InlineKeyboardButton("PGDN", callback_data="K:PGDN"),
                ],
                [
                    InlineKeyboardButton("EXIT NANO (Ctrl+X)", callback_data="K:NANO_EXIT"),
                ],
            ]
        )

    # ---------- CLOSE ----------
    def close(self):
        self.stop.set()
        try:
            if self.chan:
                try:
                    self.chan.close()
                except Exception:
                    pass
            if self.client:
                try:
                    self.client.close()
                except Exception:
                    pass
        except Exception:
            pass

        try:
            if self.message_id:
                self.bot.edit_message_text(
                    chat_id=self.chat_id,
                    message_id=self.message_id,
                    text="```Session closed```",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=None,
                )
        except Exception as e:
            logger.debug("Could not update closed message: %s", e)

        logger.info("Session closed %s", self.chat_id)


# ================= HELPERS =================
def stop_session(chat: int) -> bool:
    s = SESSIONS.pop(chat, None)
    if s:
        try:
            s.close()
        except Exception:
            logger.exception("Error closing session")
        return True
    return False


def parse_combo_tokens(tokens: List[str]) -> Tuple[List[str], str]:
    """
    tokens: a list of token strings, possibly containing '+' joined entries.
    Returns (modifiers, key)
    Modifiers are uppercased names "CTRL","ALT","SHIFT".
    Key is lowercased single token (keeps case for special keys).
    """
    merged: List[str] = []
    for t in tokens:
        # split by + as well
        parts = re.split(r"[+]", t)
        for p in parts:
            p = p.strip()
            if p:
                merged.append(p.lower())

    mods = []
    key = ""
    for tok in merged:
        if tok in ("ctrl", "control"):
            if "CTRL" not in mods:
                mods.append("CTRL")
        elif tok in ("alt", "meta"):
            if "ALT" not in mods:
                mods.append("ALT")
        elif tok in ("shift",):
            if "SHIFT" not in mods:
                mods.append("SHIFT")
        else:
            # last non-mod token is the key
            key = tok
    return mods, key


def build_sequence_from_mods_and_key(mods: List[str], key_token: str) -> str:
    """
    Build the byte sequence to send to the remote shell given modifiers and key token.
    Handles:
      - single character keys (letters/digits/symbols)
      - special named keys from KEYS dict (ENTER, TAB, UP, etc.)
    Rules:
      - If ALT present -> prefix ESC (\x1b)
      - If CTRL present and key is a single letter -> transform to control char (1-26)
      - If SHIFT present and no CTRL -> uppercase single char
      - If both ALT and CTRL -> prefix ESC then control char (common terminal behavior)
    """
    if not key_token:
        return ""

    # Special keys by name
    ukey = key_token.upper()
    if ukey in KEYS:
        seq = KEYS[ukey]
        # If ALT present, prefix ESC
        if "ALT" in mods:
            return "\x1b" + seq
        return seq

    # single-character handling
    ch = key_token
    # take first char if user sent longer token
    if len(ch) == 0:
        return ""
    ch0 = ch[0]

    seq = ""
    # alt prefix
    if "ALT" in mods:
        seq += "\x1b"

    if "CTRL" in mods:
        # only transform letters a-z to control codes
        c = ch0.lower()
        if "a" <= c <= "z":
            ctrl_char = chr(ord(c) - 96)  # ctrl-a -> 0x01 ... ctrl-z -> 0x1a
            seq += ctrl_char
            return seq
        # fallback: attempt to send chr(ord(ch0) & 0x1f)
        try:
            seq += chr(ord(ch0) & 0x1f)
            return seq
        except Exception:
            seq += ch0
            return seq
    else:
        # no CTRL: handle SHIFT by uppercasing
        if "SHIFT" in mods:
            seq += ch0.upper()
        else:
            seq += ch0
        return seq


# ================= HANDLERS =================
def start_cmd(update: Update, ctx: CallbackContext):
    chat = update.effective_chat.id
    # short start message as requested, includes hyperlinked "source code" and plain "- by @EmptyPoll"
    text = (
        "SSHBot — ready. / ربات SSH آماده است.\n\n"
        f"[source code]({REPO_URL}) - by @EmptyPoll"
    )
    update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


def help_cmd(update: Update, ctx: CallbackContext):
    chat = update.effective_chat.id
    # Put all instructions here (detailed bilingual help)
    text = (
        "HELP — Commands / راهنما — دستورات\n\n"
        "Core flow / نحوه استفاده اصلی:\n"
        "1) `/ssh user@host[:port]` — prepare a connection (then send password).\n"
        "   Example: `/ssh alice@example.com:22`\n"
        "2) `/pass <password>` — send password. The bot will delete the password message for privacy.\n"
        "   Example: `/pass mySecretPassword`\n"
        "3) Terminal appears in a pinned message; type plain messages to send text input. Your typed message will be removed from chat by the bot for privacy.\n\n"
        "Stopping / قطع سشن:\n"
        "`/stop` — stop the current SSH session.\n"
        "`/ssh` without arguments — also stops the current session.\n\n"
        "Special buttons (still available under the terminal message): TAB, ENTER, ESC, BS, ↑ ↓ ← →, PGUP, PGDN, EXIT NANO (Ctrl+X).\n\n"
        "Modifiers / ترکیب‌ها (no toggle buttons):\n"
        "Use commands to send modifier combos. Commands delete themselves (privacy):\n"
        " - `/ctrl <combo>` — send Ctrl combos. Examples:\n"
        "     `/ctrl c` -> sends Ctrl+C\n"
        "     `/ctrl alt c` -> sends Ctrl+Alt+C\n"
        "     `/ctrl ctrl+alt+c` or `/ctrl ctrl alt c` -> also accepted\n\n"
        " - `/alt <combo>` — send Alt combos. Examples:\n"
        "     `/alt a` -> sends Alt+a (ESC + 'a')\n"
        "     `/alt ctrl c` -> sends Alt+Ctrl+C\n\n"
        " - `/shift <combo>` — send Shift combos. Example: `/shift a` -> sends 'A'\n\n"
        " - `/keys <combo>` — flexible: `/keys ctrl+alt+c` or `/keys ctrl alt c` or `/keys alt+shift+x`.\n\n"
        "Notes about combos:\n"
        " - You may separate tokens by spaces or `+`.\n"
        " - Modifiers supported: ctrl, alt, shift (case-insensitive).\n"
        " - Examples:\n"
        "     `/keys ctrl+alt+c`\n"
        "     `/ctrl alt c`\n"
        "     `/alt a`\n\n"
        "Privacy & behavior / حریم خصوصی و رفتار بات:\n"
        " - Password messages sent with `/pass` will be deleted by the bot when possible.\n"
        " - Modifier/keys commands (`/ctrl`, `/alt`, `/shift`, `/keys`) attempt to delete the command message for privacy.\n"
        " - Plain messages sent while a session is active are removed from chat and forwarded to the remote shell.\n\n"
        "Troubleshooting / رفع مشکل:\n"
        " - If a session already exists and you call `/ssh user@host`, the bot will stop the previous session first.\n"
        " - If connection fails, an error message is returned and no session is kept.\n\n"
        "Examples / مثال‌ها:\n"
        "`/ssh ali@1.2.3.4`\n"
        "`/pass mypassword` (deleted)\n"
        "`/ctrl c`  -> Ctrl+C\n"
        "`/alt a`   -> Alt+a\n"
        "`/keys ctrl+alt+c` -> Ctrl+Alt+C\n\n"
        "That's all — contact the bot owner if you need custom changes. / همین— برای تغییرات بیشتر با صاحب بات تماس بگیرید."
    )
    update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


def ssh_cmd(update: Update, ctx: CallbackContext):
    chat = update.effective_chat.id

    # if user wrote /ssh without args -> treat as stop
    if not ctx.args:
        stopped = stop_session(chat)
        if stopped:
            update.message.reply_text("Stopped existing SSH session. / سشن قطع شد.")
        else:
            update.message.reply_text("No active SSH session to stop. / سشن فعالی وجود ندارد.")
        return

    # if a session exists, stop it first
    if chat in SESSIONS:
        stop_session(chat)
        update.message.reply_text("Stopped previous SSH session before starting new one. / سشن قبلی قطع شد.")

    m = SSH_RE.match(ctx.args[0]) if ctx.args else None
    if not m:
        update.message.reply_text("Usage: /ssh user@host[:port]  /  نحوه استفاده: /ssh user@host[:port]")
        return

    user, host, port = m.group(1), m.group(2), int(m.group(3) or 22)
    PENDING[chat] = (user, host, port)
    update.message.reply_text(
        "Send password using /pass <password> (message will be deleted). / برای ارسال رمز از /pass استفاده کنید (پیام حذف خواهد شد)."
    )


def pass_cmd(update: Update, ctx: CallbackContext):
    chat = update.effective_chat.id
    if chat not in PENDING:
        update.message.reply_text("No pending SSH request. Use /ssh first. / ابتدا از /ssh استفاده کنید.")
        return

    if not ctx.args:
        update.message.reply_text("Usage: /pass <password> / نحوه استفاده: /pass <رمز>")
        return

    pwd = " ".join(ctx.args)
    user, host, port = PENDING.pop(chat)

    # delete the message that contained the password if possible
    try:
        update.message.delete()
    except Exception:
        try:
            ctx.bot.delete_message(chat_id=chat, message_id=update.message.message_id)
        except Exception:
            logger.debug("Couldn't delete password message")

    sess = SSHSession(chat, ctx.bot)
    SESSIONS[chat] = sess
    ok, err = sess.start(user, host, port, pwd)
    if not ok:
        SESSIONS.pop(chat, None)
        update.message.reply_text(f"Connection failed: {err} / اتصال ناموفق: {err}")
    else:
        update.message.reply_text("Connected. Terminal is shown in the pinned message above. / متصل شد.")


def stop_cmd(update: Update, ctx: CallbackContext):
    chat = update.effective_chat.id
    s_existed = stop_session(chat)
    if s_existed:
        update.message.reply_text("Stopped SSH session. / سشن قطع شد.")
    else:
        update.message.reply_text("No active SSH session found. / سشن فعالی یافت نشد.")


def text_msg(update: Update, ctx: CallbackContext):
    chat = update.effective_chat.id
    s = SESSIONS.get(chat)
    if not s:
        return

    # remove user's message for privacy
    try:
        ctx.bot.delete_message(chat, update.message.message_id)
    except Exception:
        pass

    text = update.message.text or ""
    # send the typed text to the session (append newline)
    s.send(text + "\n")


def cb(update: Update, ctx: CallbackContext):
    q = update.callback_query
    if not q:
        return

    chat = q.message.chat_id
    s = SESSIONS.get(chat)
    if not s:
        try:
            q.answer("No active session. / سشن فعال نیست.")
            ctx.bot.edit_message_reply_markup(chat_id=chat, message_id=q.message.message_id, reply_markup=None)
        except Exception:
            pass
        return

    if q.data.startswith("K:"):
        key = q.data[2:]
        val = KEYS.get(key)
        if val is not None:
            s.send(val)
        try:
            q.answer()
        except Exception:
            pass
    else:
        try:
            q.answer()
        except Exception:
            pass


# ---------- modifier commands as per-request ----------
def process_modifier_command(primary_mod: str, update: Update, ctx: CallbackContext):
    """
    primary_mod: one of "CTRL", "ALT", "SHIFT" depending on command used.
    ctx.args may contain additional modifiers and the key to send.
    Examples user inputs:
      /ctrl c
      /ctrl alt c
      /ctrl ctrl+alt+c
    """
    chat = update.effective_chat.id
    s = SESSIONS.get(chat)
    # try to delete the command message for privacy
    try:
        update.message.delete()
    except Exception:
        pass

    if not s:
        update.message.reply_text("No active session. / سشن فعالی وجود ندارد.")
        return

    tokens = ctx.args or []
    # include primary modifier at front
    merged_tokens = [primary_mod.lower()] + tokens
    mods, key = parse_combo_tokens(merged_tokens)
    seq = build_sequence_from_mods_and_key(mods, key)
    if not seq:
        update.message.reply_text("Could not parse key. Usage: /ctrl c   or /ctrl alt c   or /keys ctrl+alt+c\n/ نتوانست کلید را پردازش کند.")
        return

    s.send(seq)
    # Optionally update keyboard UI to same terminal text (no toggles)
    try:
        if s.message_id:
            ctx.bot.edit_message_reply_markup(chat_id=chat, message_id=s.message_id, reply_markup=s.keyboard())
    except Exception:
        pass


def ctrl_cmd(update: Update, ctx: CallbackContext):
    process_modifier_command("CTRL", update, ctx)


def alt_cmd(update: Update, ctx: CallbackContext):
    process_modifier_command("ALT", update, ctx)


def shift_cmd(update: Update, ctx: CallbackContext):
    process_modifier_command("SHIFT", update, ctx)


def keys_cmd(update: Update, ctx: CallbackContext):
    """
    Generic /keys command where user may send full combo:
      /keys ctrl+alt+c
      /keys ctrl alt c
      /keys alt+shift+X
    """
    chat = update.effective_chat.id
    s = SESSIONS.get(chat)
    # delete command message for privacy
    try:
        update.message.delete()
    except Exception:
        pass

    if not s:
        update.message.reply_text("No active session. / سشن فعالی وجود ندارد.")
        return

    tokens = ctx.args or []
    if not tokens:
        update.message.reply_text("Usage: /keys ctrl+alt+c or /keys ctrl alt c\n/ نحوه استفاده: /keys ctrl+alt+c")
        return

    mods, key = parse_combo_tokens(tokens)
    seq = build_sequence_from_mods_and_key(mods, key)
    if not seq:
        update.message.reply_text("Could not parse key. / نتوانست کلید را پردازش کند.")
        return

    s.send(seq)
    try:
        if s.message_id:
            ctx.bot.edit_message_reply_markup(chat_id=chat, message_id=s.message_id, reply_markup=s.keyboard())
    except Exception:
        pass


# ================= MAIN =================
def main():
    if not BOT_TOKEN:
        print("BOT_TOKEN missing")
        return

    up = Updater(BOT_TOKEN, use_context=True)
    dp = up.dispatcher

    dp.add_handler(CommandHandler("start", start_cmd))
    dp.add_handler(CommandHandler("help", help_cmd))
    dp.add_handler(CommandHandler("ssh", ssh_cmd))
    dp.add_handler(CommandHandler("pass", pass_cmd))
    dp.add_handler(CommandHandler("stop", stop_cmd))

    # modifier commands
    dp.add_handler(CommandHandler("ctrl", ctrl_cmd))
    dp.add_handler(CommandHandler("alt", alt_cmd))
    dp.add_handler(CommandHandler("shift", shift_cmd))
    dp.add_handler(CommandHandler("keys", keys_cmd))

    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, text_msg))
    dp.add_handler(CallbackQueryHandler(cb))

    logger.info("SSH bot started")
    up.start_polling()
    up.idle()


if __name__ == "__main__":
    main()
