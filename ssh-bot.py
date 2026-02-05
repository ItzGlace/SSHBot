#!/usr/bin/env python3
"""
SSH Telegram bot — terminal SSH access over telergam

Developed by:
 - t.me/ItzGlace
 - GitHub.com/ItzGlace

"""

import os
import sys
import time
import threading
import logging
import logging.handlers
import re
from typing import Dict, Tuple, List, Optional

import paramiko
import pyte

from telegram import (
    Update,
    ParseMode,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.ext import (
    Updater,
    CommandHandler,
    MessageHandler,
    Filters,
    CallbackQueryHandler,
    CallbackContext,
)

import hashlib
import inspect
import urllib.request

# ================= CONFIG =================
BOT_TOKEN = os.environ.get("BOT_TOKEN")
TERM_COLS = 120
TERM_LINES = 200
UPDATE_INTERVAL = 1.0
MAX_TG_CHARS = 3900

LOG_DIR = "/var/log/ssh-bot"
LOG_FILE = f"{LOG_DIR}/ssh-bot.log"

REPO_URL = "https://github.com/ItzGlace/SSHBot"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/ItzGlace/SSHBot/refs/heads/main/ssh-bot.py"

# ================= LOGGING =================
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception:
    pass

logger = logging.getLogger("ssh-bot")
logger.setLevel(logging.INFO)

fmt = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
try:
    fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
except Exception:
    pass

sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(fmt)
logger.addHandler(sh)

# ================= STATE =================
SESSIONS: Dict[int, "SSHSession"] = {}
PENDING: Dict[int, Tuple[str, str, int, float]] = {}  # (user, host, port, timestamp)

SSH_RE = re.compile(r"([^@]+)@([^:]+)(?::(\d+))?$")

# core sequences (extended)
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

    # extended keys
    "INSERT": "\x1b[2~",
    "DELETE": "\x1b[3~",
    "HOME": "\x1b[1~",
    "END": "\x1b[4~",
    "SHIFTTAB": "\x1b[Z",

    # function keys (common sequences)
    "F1": "\x1bOP",
    "F2": "\x1bOQ",
    "F3": "\x1bOR",
    "F4": "\x1bOS",
    "F5": "\x1b[15~",
    "F6": "\x1b[17~",
    "F7": "\x1b[18~",
    "F8": "\x1b[19~",
    "F9": "\x1b[20~",
    "F10": "\x1b[21~",
    "F11": "\x1b[23~",
    "F12": "\x1b[24~",
}

# visible cursor char overlay
CURSOR_CHAR = "▒"

# Reply keyboard layout (native) — includes extended keys
REPLY_KEYBOARD = [
    ["TAB", "ENTER", "ESC", "BS"],
    ["↑", "↓", "←", "→"],
    ["PGUP", "PGDN", "SHIFTTAB"],
    ["INSERT", "DELETE", "HOME", "END"],
    ["F1", "F2", "F3", "F4"],
    ["F5", "F6", "F7", "F8"],
    ["F9", "F10", "F11", "F12"],
    ["EXIT NANO (Ctrl+X)"],
]

# helper mapping from label to sequence (for reply keyboard)
LABEL_TO_SEQ = {
    "TAB": KEYS["TAB"],
    "ENTER": KEYS["ENTER"],
    "ESC": KEYS["ESC"],
    "BS": KEYS["BS"],
    "↑": KEYS["UP"],
    "↓": KEYS["DOWN"],
    "←": KEYS["LEFT"],
    "→": KEYS["RIGHT"],
    "PGUP": KEYS["PGUP"],
    "PGDN": KEYS["PGDN"],
    "EXIT NANO (Ctrl+X)": KEYS["NANO_EXIT"],

    # extended
    "INSERT": KEYS["INSERT"],
    "DELETE": KEYS["DELETE"],
    "HOME": KEYS["HOME"],
    "END": KEYS["END"],
    "SHIFTTAB": KEYS["SHIFTTAB"],
    "F1": KEYS["F1"],
    "F2": KEYS["F2"],
    "F3": KEYS["F3"],
    "F4": KEYS["F4"],
    "F5": KEYS["F5"],
    "F6": KEYS["F6"],
    "F7": KEYS["F7"],
    "F8": KEYS["F8"],
    "F9": KEYS["F9"],
    "F10": KEYS["F10"],
    "F11": KEYS["F11"],
    "F12": KEYS["F12"],
}

# Inline keyboard for the console message: only Close connection (glass)
INLINE_CLOSE_KB = InlineKeyboardMarkup(
    [[InlineKeyboardButton("Close connection", callback_data="C:CLOSE")]]
)

# ================= SSH SESSION =================
class SSHSession:
    def __init__(self, chat_id: int, bot):
        self.chat_id = chat_id
        self.bot = bot

        self.client: Optional[paramiko.SSHClient] = None
        self.chan = None
        self.stop = threading.Event()
        self.thread: Optional[threading.Thread] = None

        # screen and stream from pyte (virtual terminal)
        self.screen = pyte.Screen(TERM_COLS, TERM_LINES)
        self.stream = pyte.Stream(self.screen)

        self.console_message_id: Optional[int] = None  # the pinned console message (inline KB)
        self.keyboard_message_id: Optional[int] = None  # message that set the reply keyboard

        self.last_render = ""
        self.last_sent = ""

        self.edit_failures = 0
        self._max_edit_failures = 3

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

            # send initial console message with inline Close button
            msg = self.bot.send_message(
                self.chat_id,
                text="```shell\nConnecting...\n```",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=INLINE_CLOSE_KB,
            )
            self.console_message_id = msg.message_id

            try:
                # Pin the console message if allowed
                self.bot.pin_chat_message(chat_id=self.chat_id, message_id=self.console_message_id)
            except Exception as e:
                logger.debug("Could not pin message (permission or other issue): %s", e)

            # send a separate (small) message to attach the reply keyboard for the user
            try:
                km = self.bot.send_message(
                    self.chat_id,
                    text="Control keyboard attached.",
                    reply_markup=ReplyKeyboardMarkup(REPLY_KEYBOARD, resize_keyboard=True, one_time_keyboard=False),
                )
                self.keyboard_message_id = km.message_id
            except Exception:
                # non-fatal — continue without explicit keyboard if it fails
                logger.debug("Failed to send reply keyboard message")

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
                    # feed terminal emulator
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
        """
        Render the pyte screen to text, but overlay a visible cursor at the
        current cursor coordinates so the user can see where they are editing.
        Keep the inline Close button attached to the console message.
        """
        # raw lines from pyte
        raw_lines = list(self.screen.display)

        # overlay cursor if possible
        cursor_y = getattr(self.screen, "cursor").y
        cursor_x = getattr(self.screen, "cursor").x

        lines = []
        for idx, ln in enumerate(raw_lines):
            # ensure we have a mutable copy
            sline = ln
            if idx == cursor_y:
                # pad if needed
                if len(sline) <= cursor_x:
                    sline = sline + " " * (cursor_x - len(sline) + 1)
                # replace one character at cursor_x with CURSOR_CHAR
                # build as list for safe replacement
                lchars = list(sline)
                lchars[cursor_x] = CURSOR_CHAR
                sline = "".join(lchars)
            lines.append(sline)

        text = "\n".join(lines).rstrip()

        if text == self.last_render:
            return

        self.last_render = text
        safe = self.clamp(text)

        if safe == self.last_sent:
            return

        payload = f"```shell\n{safe}\n```"

        try:
            # edit the existing console message and keep the Close glass button
            if self.console_message_id:
                self.bot.edit_message_text(
                    chat_id=self.chat_id,
                    message_id=self.console_message_id,
                    text=payload,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=INLINE_CLOSE_KB,
                )
                self.last_sent = safe
                self.edit_failures = 0
            else:
                # no existing message - send one with only Close glass button
                msg = self.bot.send_message(
                    chat_id=self.chat_id,
                    text=payload,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=INLINE_CLOSE_KB,
                )
                self.console_message_id = msg.message_id
                self.last_sent = safe

        except Exception as e:
            logger.warning("Edit failed: %s", e)
            self.edit_failures += 1
            # if we've failed multiple edits, send a fresh message and switch to it
            if self.edit_failures >= self._max_edit_failures:
                try:
                    msg = self.bot.send_message(
                        chat_id=self.chat_id,
                        text=payload,
                        parse_mode=ParseMode.MARKDOWN,
                        reply_markup=INLINE_CLOSE_KB,
                    )
                    self.console_message_id = msg.message_id
                    self.last_sent = safe
                    self.edit_failures = 0
                except Exception as ee:
                    logger.exception("Failed to send fallback message: %s", ee)

    # ---------- CLAMP ----------
    def clamp(self, text: str) -> str:
        """Return the trailing part of `text` that fits within MAX_TG_CHARS."""
        if len(text) <= MAX_TG_CHARS:
            return text

        lines = text.splitlines()
        out_lines: List[str] = []
        total = 0
        # iterate from the end and accumulate
        for line in reversed(lines):
            l = len(line) + (1 if out_lines else 0)  # account for newline if not the last
            if total + l > MAX_TG_CHARS:
                break
            out_lines.append(line)
            total += l

        out_lines.reverse()
        return "\n".join(out_lines)

    # ---------- INPUT ----------
    def send(self, text: str):
        """
        Send text to the remote channel. Text may contain control characters.
        We send as-is (no automatic newline) but send it char-by-char so partial
        typed messages behave like typing.
        """
        try:
            if self.chan and not self.stop.is_set():
                # send character-by-character to emulate typing & allow immediate processing
                for ch in text:
                    self.chan.send(ch)
        except Exception:
            logger.exception("Send failed")

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

        # update the terminal message to show the session closed and remove user's keyboard
        try:
            if self.console_message_id:
                self.bot.edit_message_text(
                    chat_id=self.chat_id,
                    message_id=self.console_message_id,
                    text="```shell\nSession closed\n```",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=None,
                )
                # attempt to unpin the message
                try:
                    self.bot.unpin_chat_message(chat_id=self.chat_id)
                except Exception as e:
                    logger.debug("Could not unpin message: %s", e)
            # remove native reply keyboard by sending a small message
            try:
                self.bot.send_message(chat_id=self.chat_id, text="Keyboard removed.", reply_markup=ReplyKeyboardRemove())
            except Exception:
                pass
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

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def compute_local_hash() -> str:
    path = inspect.getsourcefile(lambda: None)
    if not path:
        return "UNKNOWN"
    with open(path, "rb") as f:
        return sha256_bytes(f.read())


def compute_remote_hash(timeout: int = 10) -> str:
    req = urllib.request.Request(
        GITHUB_RAW_URL,
        headers={"User-Agent": "SSHBot-Integrity-Check"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return sha256_bytes(r.read())


# ================= HANDLERS =================
def start_cmd(update: Update, ctx: CallbackContext):
    text = (
        "SSHBot / ربات SSH\n\n"
        "Help / راهنما : /help\n"
        "Hash-Check / بررسی هش ربات : /hash\n"
        "\n"
        f"[source code]({REPO_URL}) - by @EmptyPoll"
    )
    update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


def help_cmd(update: Update, ctx: CallbackContext):
    text = (
        "HELP — Commands / راهنما — دستورات\n\n"
        "Core flow:\n"
        "1) `/hash — compare the hash of the running bot with the source code for backdoor safety.\n"
        "2) `/ssh user@host[:port]` — prepare a connection (then send password).\n"
        "3) `/pass <password>` — send password (deleted by bot when possible).\n"
        "4) Type to edit input (no automatic newline). Use ENTER button to submit newline.\n\n"
        "Buttons: TAB, ENTER, ESC, BS (Backspace), arrows, PGUP, PGDN, Insert, Delete, Home, End, Shift+Tab, F1..F12.\n"
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
    # store timestamp so we can expire stale pending requests if desired
    PENDING[chat] = (user, host, port, time.time())
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
    user, host, port, _ts = PENDING.pop(chat)

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

    # zero the password variable as soon as possible
    try:
        pwd = None
        del pwd
    except Exception:
        pass

    if not ok:
        SESSIONS.pop(chat, None)
        update.message.reply_text(f"Connection failed: {err} / اتصال ناموفق: {err}")
    else:
        logger.info("Session started for chat %s", chat)


def stop_cmd(update: Update, ctx: CallbackContext):
    chat = update.effective_chat.id
    s_existed = stop_session(chat)
    if s_existed:
        update.message.reply_text("Stopped SSH session. / سشن قطع شد.")
    else:
        update.message.reply_text("No active SSH session found. / سشن فعادی یافت نشد.")


def text_msg(update: Update, ctx: CallbackContext):
    """
    Handles plain text messages from the user:
     - Delete the message in chat for privacy.
     - If the message matches one of the reply keyboard labels, send the
       corresponding control sequence.
     - Otherwise, forward content character-by-character (no automatic newline).
    """
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

    # if user pressed a keyboard button, translate to sequence
    seq = LABEL_TO_SEQ.get(text)
    if seq is not None:
        s.send(seq)
        return

    # otherwise, send typed characters as-is (no newline appended)
    s.send(text)


def cb(update: Update, ctx: CallbackContext):
    q = update.callback_query
    if not q:
        return

    chat = q.message.chat_id
    s = SESSIONS.get(chat)
    data = q.data or ""

    # Close connection button
    if data == "C:CLOSE":
        try:
            q.answer("Closing connection...")
        except Exception:
            pass
        # trigger stop (this will edit the console message and remove keyboard)
        stop_session(chat)
        return

    # Key callbacks are not present on glass anymore; if ever received, handle K:*
    if data.startswith("K:"):
        key = data[2:]
        if not s:
            try:
                q.answer("No active session. / سشن فعال نیست.")
            except Exception:
                pass
            return

        val = KEYS.get(key)
        if val is not None:
            s.send(val)
        try:
            q.answer()
        except Exception:
            pass
        return

    try:
        q.answer()
    except Exception:
        pass

def hash_cmd(update: Update, ctx: CallbackContext):
    try:
        local_hash = compute_local_hash()
        remote_hash = compute_remote_hash()

        if local_hash == remote_hash:
            update.message.reply_text(
                "✅ *Integrity verified*\n"
                "Running code matches GitHub exactly.\n\n"
                f"`{local_hash}`",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            update.message.reply_text(
                "❌ *Integrity check FAILED*\n"
                "This bot is MODIFIED.\n\n"
                f"*Local:*\n`{local_hash}`\n\n"
                f"*GitHub:*\n`{remote_hash}`",
                parse_mode=ParseMode.MARKDOWN,
            )
    except Exception as e:
        update.message.reply_text(
            "⚠️ *Integrity check error*\n"
            f"Could not reach GitHub.\n\n`{e}`",
            parse_mode=ParseMode.MARKDOWN,
        )



# ---------- modifier commands as per-request ----------
def process_modifier_command(primary_mod: str, update: Update, ctx: CallbackContext):
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
        update.message.reply_text("Could not parse key. Usage: /ctrl c   or /keys ctrl+alt+c")
        return

    s.send(seq)


def ctrl_cmd(update: Update, ctx: CallbackContext):
    process_modifier_command("CTRL", update, ctx)


def alt_cmd(update: Update, ctx: CallbackContext):
    process_modifier_command("ALT", update, ctx)


def shift_cmd(update: Update, ctx: CallbackContext):
    process_modifier_command("SHIFT", update, ctx)


def keys_cmd(update: Update, ctx: CallbackContext):
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
        update.message.reply_text("Usage: /keys ctrl+alt+c or /keys ctrl alt c")
        return

    mods, key = parse_combo_tokens(tokens)
    seq = build_sequence_from_mods_and_key(mods, key)
    if not seq:
        update.message.reply_text("Could not parse key. / نتوانست کلید را پردازش کند.")
        return

    s.send(seq)


# ================= MAIN =================
def main():
    if not BOT_TOKEN:
        print("BOT_TOKEN missing")
        return

    up = Updater(BOT_TOKEN, use_context=True)
    dp = up.dispatcher

    dp.add_handler(CommandHandler("start", start_cmd))
    dp.add_handler(CommandHandler("help", help_cmd))
    dp.add_handler(CommandHandler("hash", hash_cmd))
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
