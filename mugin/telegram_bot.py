"""Telegram adapter skeleton.

This module intentionally does not execute arbitrary shell commands. Add the
BOT_TOKEN only as a GitHub Actions secret or runtime environment variable.
"""
from __future__ import annotations

import os

ALLOWED_COMMANDS = {
    "/start": "عرض القائمة",
    "/list": "عرض التحديات المتاحة",
    "/policy": "عرض سياسة النطاق",
    "/dryrun": "تشغيل محاكاة على هدف محلي فقط",
}


def command_menu() -> list[str]:
    return [f"{command} — {description}" for command, description in ALLOWED_COMMANDS.items()]


def is_authorized(user_id: int, owner_ids: set[int]) -> bool:
    return user_id in owner_ids


def configuration_status() -> dict:
    return {
        "configured": bool(os.getenv("TELEGRAM_BOT_TOKEN")),
        "mode": "restricted-local-labs",
        "arbitrary_shell": False,
        "public_targets": False,
    }


if __name__ == "__main__":
    print("Mugin Telegram adapter is a safe skeleton; connect a framework explicitly.")
    print("\n".join(command_menu()))
