from __future__ import annotations

import json
from datetime import datetime

from .cli import CHALLENGES, safe_check
from .core import PolicyError, policy_summary


def pause() -> None:
    input("\nPress Enter to return to the menu...")


def print_header() -> None:
    print("\n" + "=" * 58)
    print("                 MUGIN | ETHICAL LAB")
    print("=" * 58)
    print("Mode: local labs / safe simulation only")


def show_menu() -> None:
    print_header()
    options = [
        "List training challenges",
        "Show security and scope policy",
        "Check a local target in simulation mode",
        "Create a JSON check report",
        "Show system status",
        "Exit",
    ]
    for number, label in enumerate(options, 1):
        print(f"  {number}. {label}")


def choose_target() -> str | None:
    print("\nEnter a local or private target that you own, e.g. http://127.0.0.1:8080")
    target = input("Target: ").strip()
    if not target:
        print("No target entered.")
        return None
    return target


def main() -> None:
    while True:
        show_menu()
        choice = input("\nChoose a number: ").strip()
        if choice == "1":
            print("\nAvailable challenges:")
            for item in CHALLENGES:
                print(f"  [{item['id']}] {item['title']} — level: {item['level']}")
            pause()
        elif choice == "2":
            print(json.dumps(policy_summary(), ensure_ascii=False, indent=2))
            pause()
        elif choice in {"3", "4"}:
            target = choose_target()
            if target:
                try:
                    findings = [f.__dict__ for f in safe_check(target, dry_run=True)]
                    print("\nCheck result:")
                    print(json.dumps(findings, ensure_ascii=False, indent=2))
                    if choice == "4":
                        filename = f"mugin-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
                        with open(filename, "w", encoding="utf-8") as report:
                            json.dump({"target": target, "findings": findings}, report, ensure_ascii=False, indent=2)
                        print(f"\nReport saved: {filename}")
                except PolicyError as error:
                    print(f"\nOperation rejected by the safety policy: {error}")
                pause()
        elif choice == "5":
            print("\nStatus: ready")
            print("Engine: active")
            print("Default mode: dry-run")
            print("Public targets: blocked")
            pause()
        elif choice == "6":
            print("Goodbye.")
            return
        else:
            print("Invalid choice. Select a number from 1 to 6.")


if __name__ == "__main__":
    main()
