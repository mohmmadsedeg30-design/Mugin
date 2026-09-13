from __future__ import annotations

import json
from datetime import datetime

from .cli import CHALLENGES, safe_check
from .core import PolicyError, policy_summary


def pause() -> None:
    input("\nاضغط Enter للعودة إلى القائمة...")


def print_header() -> None:
    print("\n" + "=" * 58)
    print("                 MUGIN | المختبر الأخلاقي")
    print("=" * 58)
    print("الوضع: مختبرات محلية / محاكاة آمنة فقط")


def show_menu() -> None:
    print_header()
    options = [
        "عرض التحديات التعليمية",
        "عرض سياسة الأمان والنطاق",
        "فحص هدف محلي في وضع المحاكاة",
        "إنشاء تقرير فحص JSON",
        "عرض حالة النظام",
        "خروج",
    ]
    for number, label in enumerate(options, 1):
        print(f"  {number}. {label}")


def choose_target() -> str | None:
    print("\nأدخل رابط هدف محلي أو خاص تملكه، مثل http://127.0.0.1:8080")
    target = input("الهدف: ").strip()
    if not target:
        print("لم يتم إدخال هدف.")
        return None
    return target


def main() -> None:
    while True:
        show_menu()
        choice = input("\nاختر رقماً: ").strip()
        if choice == "1":
            print("\nالتحديات المتاحة:")
            for item in CHALLENGES:
                print(f"  [{item['id']}] {item['title']} — المستوى: {item['level']}")
            pause()
        elif choice == "2":
            print(json.dumps(policy_summary(), ensure_ascii=False, indent=2))
            pause()
        elif choice in {"3", "4"}:
            target = choose_target()
            if target:
                try:
                    findings = [f.__dict__ for f in safe_check(target, dry_run=True)]
                    print("\nنتيجة الفحص:")
                    print(json.dumps(findings, ensure_ascii=False, indent=2))
                    if choice == "4":
                        filename = f"mugin-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
                        with open(filename, "w", encoding="utf-8") as report:
                            json.dump({"target": target, "findings": findings}, report, ensure_ascii=False, indent=2)
                        print(f"\nتم حفظ التقرير: {filename}")
                except PolicyError as error:
                    print(f"\nتم رفض العملية وفق سياسة الأمان: {error}")
                pause()
        elif choice == "5":
            print("\nالحالة: جاهز")
            print("المحرك: فعال")
            print("الوضع الافتراضي: dry-run")
            print("الأهداف العامة: محظورة")
            pause()
        elif choice == "6":
            print("إلى اللقاء.")
            return
        else:
            print("اختيار غير صحيح. اختر رقماً من 1 إلى 6.")


if __name__ == "__main__":
    main()
