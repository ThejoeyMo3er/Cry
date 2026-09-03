import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ============================================================
# Configuration
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

PANTEGNOS_BIN = os.getenv(
    "PANTEGNOS_BIN",
    "/opt/pantegnos/pantegnos",
)

MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(50 * 1024 * 1024)))
PROCESS_TIMEOUT = int(os.getenv("PROCESS_TIMEOUT", "60"))

# Telegram message text limit is ~4096.
# Keep a safety margin.
MESSAGE_LIMIT = 3900

SUPPORTED_EXTENSIONS = {
    ".slip",
    ".ehi",
    ".dark",
    ".hat",
    ".npvt",
    ".npvs",
    ".nm",
    ".happ",
}

# Common V2Ray / proxy URI schemes.
URI_SCHEMES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "socks://",
    "socks5://",
    "http://",
    "https://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "wireguard://",
    "ssh://",
)

# Generic URL-ish matcher.
URL_RE = re.compile(
    r"(?i)(?:"
    r"vless|vmess|trojan|ss|socks5?|hysteria2?|hy2|tuic|wireguard|ssh"
    r")://[^\s<>\[\]{}\"']+"
)

# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger("pantegnos-bot")


# ============================================================
# Helpers
# ============================================================

def ensure_configured():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN is not set")

    if not os.path.isfile(PANTEGNOS_BIN):
        raise RuntimeError(
            f"Pantegnos binary not found: {PANTEGNOS_BIN}"
        )


def normalize_link(link: str) -> str:
    """
    Remove characters that are commonly captured accidentally
    at the end of a URI.
    """
    return link.strip().rstrip(".,;)]}>'\"")


def extract_links(text: str) -> list[str]:
    """
    Extract supported proxy/V2Ray links from arbitrary text.
    Keeps order and removes duplicates.
    """
    found = []

    for match in URL_RE.findall(text or ""):
        link = normalize_link(match)

        if not link:
            continue

        lower = link.lower()

        if not lower.startswith(URI_SCHEMES):
            continue

        if link not in found:
            found.append(link)

    return found


def split_message(text: str, limit: int = MESSAGE_LIMIT) -> list[str]:
    """
    Split long output into Telegram-safe messages.
    """
    if len(text) <= limit:
        return [text]

    chunks = []
    current = ""

    for line in text.splitlines(True):
        if len(current) + len(line) <= limit:
            current += line
        else:
            if current:
                chunks.append(current)
            current = line

    if current:
        chunks.append(current)

    # Extremely long single lines.
    final_chunks = []

    for chunk in chunks:
        while len(chunk) > limit:
            final_chunks.append(chunk[:limit])
            chunk = chunk[limit:]

        if chunk:
            final_chunks.append(chunk)

    return final_chunks


def format_links(links: list[str]) -> str:
    """
    Create a compact Telegram-friendly list.
    """
    lines = [
        "🔗 <b>V2Ray / Proxy Links</b>",
        f"📦 تعداد: <b>{len(links)}</b>",
        "",
    ]

    for i, link in enumerate(links, 1):
        lines.append(f"<b>{i}.</b> <code>{escape_html(link)}</code>")

    return "\n".join(lines)


def escape_html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def make_json(links: list[str], source_files: list[str]) -> str:
    data = {
        "source": "Pantegnos Telegram Bot",
        "files": source_files,
        "count": len(links),
        "links": [
            {
                "protocol": get_protocol(link),
                "link": link,
            }
            for link in links
        ],
    }

    return json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
    )


def get_protocol(link: str) -> str:
    try:
        return link.split("://", 1)[0].lower()
    except Exception:
        return "unknown"


def make_info(links: list[str], source_files: list[str]) -> str:
    protocols = {}

    for link in links:
        protocol = get_protocol(link)
        protocols[protocol] = protocols.get(protocol, 0) + 1

    lines = [
        "🔍 <b>Configuration Information</b>",
        "",
        f"📁 Files: <b>{len(source_files)}</b>",
        f"🔗 Links: <b>{len(links)}</b>",
    ]

    if protocols:
        lines.append("")
        lines.append("📡 <b>Protocols:</b>")

        for protocol, count in sorted(protocols.items()):
            lines.append(
                f"• <code>{escape_html(protocol)}</code>: {count}"
            )

    return "\n".join(lines)


def build_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "🔗 لینک‌های V2Ray",
                    callback_data=f"links:{user_id}",
                ),
                InlineKeyboardButton(
                    "📋 JSON",
                    callback_data=f"json:{user_id}",
                ),
            ],
            [
                InlineKeyboardButton(
                    "🔍 اطلاعات",
                    callback_data=f"info:{user_id}",
                ),
                InlineKeyboardButton(
                    "📄 خروجی خام",
                    callback_data=f"raw:{user_id}",
                ),
            ],
            [
                InlineKeyboardButton(
                    "🗑 حذف",
                    callback_data=f"delete:{user_id}",
                )
            ],
        ]
    )


# ============================================================
# Pantegnos
# ============================================================

async def run_pantegnos(input_dir: Path, output_dir: Path):
    """
    Execute the Pantegnos CLI.

    Current Pantegnos CLI:
        ./Pantegnos -input configs -output output
    """

    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        PANTEGNOS_BIN,
        "-input",
        str(input_dir),
        "-output",
        str(output_dir),
    ]

    logger.info("Running Pantegnos: %s", command)

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=PROCESS_TIMEOUT,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError(
            f"Pantegnos timed out after {PROCESS_TIMEOUT}s"
        )

    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")

    if process.returncode != 0:
        logger.error(
            "Pantegnos failed: stdout=%s stderr=%s",
            stdout_text,
            stderr_text,
        )

        raise RuntimeError(
            "Pantegnos failed.\n"
            + (stderr_text[-1500:] or stdout_text[-1500:])
        )

    return stdout_text, stderr_text


def collect_output_files(output_dir: Path) -> list[Path]:
    if not output_dir.exists():
        return []

    return sorted(
        p for p in output_dir.rglob("*")
        if p.is_file()
    )


def read_all_output(files: list[Path]) -> tuple[str, list[str]]:
    parts = []
    names = []

    for path in files:
        try:
            content = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except Exception as exc:
            logger.warning(
                "Could not read %s: %s",
                path,
                exc,
            )
            continue

        names.append(path.name)

        parts.append(
            f"\n===== {path.name} =====\n"
            f"{content}\n"
        )

    return "\n".join(parts), names


# ============================================================
# Temporary job storage
# ============================================================

# user_id -> current job
USER_JOBS: dict[int, dict] = {}


def cleanup_job(user_id: int):
    job = USER_JOBS.pop(user_id, None)

    if not job:
        return

    directory = job.get("directory")

    if directory:
        shutil.rmtree(directory, ignore_errors=True)


# ============================================================
# Telegram handlers
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "👋 <b>Pantegnos Config Bot</b>\n\n"
        "فایل کانفیگ پشتیبانی‌شده را ارسال کن.\n"
        "بعد از پردازش می‌توانی:\n\n"
        "🔗 همه لینک‌ها را بگیری\n"
        "📋 JSON بگیری\n"
        "🔍 اطلاعات کانفیگ را ببینی\n"
        "📄 خروجی خام Pantegnos را دریافت کنی\n\n"
        "همچنین می‌توانی مستقیماً یک لینک "
        "VLESS / VMess / Trojan / SS و ... ارسال کنی."
    )

    await update.message.reply_text(
        text,
        parse_mode=ParseMode.HTML,
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return

    text = update.message.text.strip()
    links = extract_links(text)

    if not links:
        await update.message.reply_text(
            "❌ لینک قابل شناسایی پیدا نشد."
        )
        return

    user_id = update.effective_user.id

    cleanup_job(user_id)

    USER_JOBS[user_id] = {
        "directory": None,
        "raw": text,
        "output": text,
        "links": links,
        "source_files": ["direct-message"],
    }

    await update.message.reply_text(
        "✅ لینک دریافت شد.\n\n"
        f"🔗 {len(links)} لینک پیدا شد.\n"
        "انتخاب کن:",
        reply_markup=build_keyboard(user_id),
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.document:
        return

    document = update.message.document
    user_id = update.effective_user.id

    # Telegram may not always expose exact size.
    if document.file_size and document.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(
            f"❌ حجم فایل بیش از حد مجاز است.\n"
            f"حداکثر: {MAX_FILE_SIZE // (1024 * 1024)} MB"
        )
        return

    filename = document.file_name or "config.bin"
    extension = Path(filename).suffix.lower()

    if extension not in SUPPORTED_EXTENSIONS:
        await update.message.reply_text(
            "⚠️ پسوند این فایل در لیست فرمت‌های شناخته‌شده "
            "Pantegnos نیست.\n\n"
            "اگر مطمئنی فایل کانفیگ است، می‌توانی ارسالش کنی؛ "
            "اما ممکن است Pantegnos نتواند آن را پردازش کند."
        )

    status = await update.message.reply_text(
        "⏳ فایل دریافت شد.\n"
        "در حال پردازش با Pantegnos..."
    )

    work_dir = Path(
        tempfile.mkdtemp(prefix="pantegnos-")
    )

    input_dir = work_dir / "configs"
    output_dir = work_dir / "output"

    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        telegram_file = await document.get_file()

        input_file = input_dir / filename

        await telegram_file.download_to_drive(
            custom_path=str(input_file)
        )

        actual_size = input_file.stat().st_size

        if actual_size > MAX_FILE_SIZE:
            raise RuntimeError(
                f"File is larger than allowed size "
                f"({MAX_FILE_SIZE} bytes)"
            )

        await run_pantegnos(
            input_dir,
            output_dir,
        )

        output_files = collect_output_files(output_dir)

        if not output_files:
            raise RuntimeError(
                "Pantegnos produced no output files."
            )

        raw_output, source_files = read_all_output(
            output_files
        )

        links = extract_links(raw_output)

        # Also search the original file when possible.
        # This catches plaintext URI content that Pantegnos
        # might not copy into the final text.
        try:
            original_bytes = input_file.read_bytes()

            original_text = original_bytes.decode(
                "utf-8",
                errors="ignore",
            )

            for link in extract_links(original_text):
                if link not in links:
                    links.append(link)

        except Exception as exc:
            logger.warning(
                "Could not scan original file: %s",
                exc,
            )

        USER_JOBS[user_id] = {
            "directory": str(work_dir),
            "raw": raw_output,
            "output": raw_output,
            "links": links,
            "source_files": source_files or [filename],
        }

        await status.edit_text(
            "✅ <b>پردازش تمام شد.</b>\n\n"
            f"📁 فایل: <code>{escape_html(filename)}</code>\n"
            f"🔗 لینک پیدا شده: <b>{len(links)}</b>\n\n"
            "یکی از گزینه‌ها را انتخاب کن:",
            parse_mode=ParseMode.HTML,
            reply_markup=build_keyboard(user_id),
        )

    except Exception as exc:
        logger.exception("Processing failed")

        cleanup_job(user_id)

        await status.edit_text(
            "❌ <b>پردازش فایل ناموفق بود.</b>\n\n"
            f"<code>{escape_html(str(exc)[-2500:])}</code>",
            parse_mode=ParseMode.HTML,
        )


# ============================================================
# Button handler
# ============================================================

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query

    if not query:
        return

    await query.answer()

    try:
        action, owner_id = query.data.split(":", 1)
        owner_id = int(owner_id)
    except Exception:
        await query.edit_message_text(
            "❌ درخواست نامعتبر."
        )
        return

    # Don't allow another user to access the job.
    if update.effective_user.id != owner_id:
        await query.answer(
            "این فایل متعلق به کاربر دیگری است.",
            show_alert=True,
        )
        return

    job = USER_JOBS.get(owner_id)

    if not job:
        await query.edit_message_text(
            "⚠️ اطلاعات این فایل دیگر در حافظه بات نیست.\n"
            "لطفاً فایل را دوباره ارسال کن."
        )
        return

    links = job.get("links", [])
    raw = job.get("raw", "")
    source_files = job.get("source_files", [])

    # --------------------------------------------------------
    # Links
    # --------------------------------------------------------

    if action == "links":
        if not links:
            await query.edit_message_text(
                "❌ هیچ لینک V2Ray/Proxy از فایل استخراج نشد.",
                reply_markup=build_keyboard(owner_id),
            )
            return

        await query.edit_message_text(
            f"🔗 <b>{len(links)} لینک پیدا شد.</b>\n"
            "در حال ارسال...",
            parse_mode=ParseMode.HTML,
        )

        text = format_links(links)

        for chunk in split_message(text):
            await query.message.reply_text(
                chunk,
                parse_mode=ParseMode.HTML,
            )

        return

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    if action == "json":
        json_text = make_json(
            links,
            source_files,
        )

        # Telegram's text message limit.
        if len(json_text) <= MESSAGE_LIMIT:
            await query.edit_message_text(
                f"<pre>{escape_html(json_text)}</pre>",
                parse_mode=ParseMode.HTML,
                reply_markup=build_keyboard(owner_id),
            )
        else:
            # Send JSON as a file.
            temporary = Path(
                tempfile.mktemp(
                    prefix="pantegnos-",
                    suffix=".json",
                )
            )

            try:
                temporary.write_text(
                    json_text,
                    encoding="utf-8",
                )

                await query.edit_message_text(
                    "📋 JSON آماده شد. در حال ارسال فایل..."
                )

                with temporary.open("rb") as file:
                    await query.message.reply_document(
                        document=file,
                        filename="configs.json",
                    )

            finally:
                temporary.unlink(
                    missing_ok=True
                )

        return

    # --------------------------------------------------------
    # Info
    # --------------------------------------------------------

    if action == "info":
        info = make_info(
            links,
            source_files,
        )

        await query.edit_message_text(
            info,
            parse_mode=ParseMode.HTML,
            reply_markup=build_keyboard(owner_id),
        )

        return

    # --------------------------------------------------------
    # Raw
    # --------------------------------------------------------

    if action == "raw":
        if not raw:
            await query.edit_message_text(
                "❌ خروجی خامی وجود ندارد.",
                reply_markup=build_keyboard(owner_id),
            )
            return

        temporary = Path(
            tempfile.mktemp(
                prefix="pantegnos-",
                suffix=".txt",
            )
        )

        try:
            temporary.write_text(
                raw,
                encoding="utf-8",
            )

            await query.edit_message_text(
                "📄 خروجی خام آماده شد. در حال ارسال..."
            )

            with temporary.open("rb") as file:
                await query.message.reply_document(
                    document=file,
                    filename="pantegnos-output.txt",
                )

        finally:
            temporary.unlink(
                missing_ok=True
            )

        return

    # --------------------------------------------------------
    # Delete
    # --------------------------------------------------------

    if action == "delete":
        cleanup_job(owner_id)

        await query.edit_message_text(
            "🗑 اطلاعات و فایل موقت حذف شد."
        )

        return


# ============================================================
# Error handler
# ============================================================

async def error_handler(
    update: object,
    context: ContextTypes.DEFAULT_TYPE,
):
    logger.exception(
        "Unhandled exception",
        exc_info=context.error,
    )


# ============================================================
# Main
# ============================================================

def main():
    ensure_configured()

    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    application.add_handler(
        CommandHandler("start", start)
    )

    application.add_handler(
        MessageHandler(
            filters.Document.ALL,
            handle_document,
        )
    )

    application.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            handle_text,
        )
    )

    application.add_handler(
        CallbackQueryHandler(button_handler)
    )

    application.add_error_handler(
        error_handler
    )

    logger.info(
        "Bot started. Pantegnos: %s",
        PANTEGNOS_BIN,
    )

    application.run_polling(
        allowed_updates=Update.ALL_TYPES,
    )


if __name__ == "__main__":
    main()