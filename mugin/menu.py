from __future__ import annotations

import json
from datetime import datetime

from .cli import CHALLENGES, safe_check
from .core import PolicyError, policy_summary, review_security_headers

BANNER = r"""
 __  __ _   _  ____ ___ _   _
|  \/  | | | |/ ___|_ _| \ | |
| |\/| | | | | |  _ | ||  \| |
| |  | | |_| | |_| || || |\  |
|_|  |_|\___/ \____|___|_| \_|
        SAFE ETHICAL LAB
"""

MENU_OPTIONS = (
    "List training challenges",
    "Show safety policy",
    "Run a local dry-run check",
    "Create a local JSON report",
    "Review supplied security headers offline",
    "Show Telegram adapter status",
    "Show legal and safety disclaimer",
    "Exit",
)


def pause() -> None:
    input("\nPress Enter to return to the menu...")


def print_header() -> None:
    print(BANNER)
    print("Mode: authorized local labs / offline simulation only")
    print("Public targets: blocked | Credential collection: disabled")


def show_menu() -> None:
    print_header()
    print("\nMain menu")
    for number, label in enumerate(MENU_OPTIONS, 1):
        print(f"  {number}. {label}")


def choose_target() -> str | None:
    print("\nEnter a local or private target that you own, for example:")
    target = input("Target: ").strip()
    if not target:
        print("No target entered.")
        return None
    return target


def choose_headers() -> dict[str, str]:
    print("\nEnter local lab response headers as Name: Value.")
    print("Submit an empty line when finished. Values are not printed or stored.")
    headers: dict[str, str] = {}
    while True:
        line = input("Header: ").strip()
        if not line:
            return headers
        if ":" not in line:
            print("Invalid format. Use Name: Value.")
            continue
        name, value = line.split(":", 1)
        if name.strip():
            headers[name.strip()] = value.strip()


def print_disclaimer() -> None:
    print(
        """
DISCLAIMER
==========
Mugin is an educational defensive tool for systems that you own or are
explicitly authorized to test. It is not a phishing toolkit and must not be
used to create deceptive login pages, collect credentials, bypass access
controls, scan public systems, deliver malware, persist, evade detection, or
disrupt services. All checks are local, low-impact, and intended for isolated
training labs. You are solely responsible for authorization and lawful use.
""".strip()
    )


def main() -> None:
    while True:
        show_menu()
        choice = input("\nChoose a number: ").strip()
        if choice == "1":
            print("\nAvailable challenges:")
            for item in CHALLENGES:
                print(f"  [{item['id']}] {item['title']} - level: {item['level']}")
            pause()
        elif choice == "2":
            print(json.dumps(policy_summary(), indent=2))
            pause()
        elif choice in {"3", "4"}:
            target = choose_target()
            if target:
                try:
                    findings = [f.__dict__ for f in safe_check(target, dry_run=True)]
                    print("\nCheck result:")
                    print(json.dumps(findings, indent=2))
                    if choice == "4":
                        filename = f"mugin-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
                        with open(filename, "w", encoding="utf-8") as report:
                            json.dump({"target": target, "findings": findings}, report, indent=2)
                        print(f"\nReport saved locally: {filename}")
                except PolicyError as error:
                    print(f"\nOperation rejected by the safety policy: {error}")
                pause()
        elif choice == "5":
            findings = review_security_headers(choose_headers())
            print("\nOffline review result:")
            print(json.dumps([finding.__dict__ for finding in findings], indent=2))
            pause()
        elif choice == "6":
            from .telegram_bot import configuration_status
            print("\nTelegram adapter status:")
            print(json.dumps(configuration_status(), indent=2))
            print("The repository contains only a restricted adapter skeleton.")
            pause()
        elif choice == "7":
            print_disclaimer()
            pause()
        elif choice == "8":
            print("Goodbye.")
            return
        else:
            print(f"Invalid choice. Select a number from 1 to {len(MENU_OPTIONS)}.")


if __name__ == "__main__":
    main()


__all__ = ["BANNER", "MENU_OPTIONS", "main", "print_disclaimer"]
