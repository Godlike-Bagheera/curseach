"""Генерация секции «Проверки сканера» в about.html из единого источника.

Источник: CHECK_METADATA (checks/__init__.py) + get_vuln_info (descriptions.py)
через build_registry() (scanner/vuln_guide.py). Маркеры CHECKS:START/END.

Запуск:
    python scripts/gen_about.py          # перегенерировать about.html
    python scripts/gen_about.py --check  # exit 1, если about.html рассинхронизирован
"""

import argparse
import html
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START = "<!-- CHECKS:START -->"
END = "<!-- CHECKS:END -->"


def render_checks(registry: list[dict]) -> str:
    """HTML-блок списка проверок (таблица) из реестра build_registry()."""
    rows = []
    for r in registry:
        name = html.escape(r["name"])
        cid = html.escape(r["id"])
        en = html.escape(r["title_en"])
        level = html.escape(r["level"])
        codes = html.escape(", ".join(r["cwe"] + r["owasp_api"]) or "—")
        meaning = html.escape(r["meaning"] or "—")
        rows.append(
            "                    <tr>\n"
            f"                        <td><b>{name}</b><br><code>{cid}</code><br><code>{en}</code></td>\n"
            f'                        <td class="level-cell">{level}</td>\n'
            f"                        <td>{codes}</td>\n"
            f"                        <td>{meaning}</td>\n"
            "                    </tr>"
        )
    return (
        f"            <p>Всего реализовано <strong>{len(registry)} проверок</strong>. "
        "Список генерируется из <code>CHECK_METADATA</code> + <code>descriptions.py</code> "
        "(<code>scripts/gen_about.py</code>) — единый источник с /vulns и отчётами.</p>\n\n"
        '            <table class="data-table">\n'
        "                <thead>\n"
        "                    <tr>\n"
        '                        <th style="width: 240px;">Проверка</th>\n'
        '                        <th class="level-head">Уровень</th>\n'
        '                        <th style="width: 200px;">CWE / OWASP</th>\n'
        "                        <th>Что проверяется</th>\n"
        "                    </tr>\n"
        "                </thead>\n"
        "                <tbody>\n" + "\n".join(rows) + "\n                </tbody>\n            </table>"
    )


def apply(text: str, block: str) -> str:
    """Вставляет блок между CHECKS:START/END в секции id=checks (идемпотентно)."""
    i = text.index('<section id="checks">')
    title_end = text.index("</div>", i) + len("</div>")
    j = text.index("</section>", i)
    inner = "\n            " + START + "\n" + block + "\n            " + END + "\n        "
    return text[:title_end] + inner + text[j:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="только проверить синхронность (exit 1 при рассинхроне)")
    args = ap.parse_args()
    sys.path.insert(0, ROOT)
    from scanner.vuln_guide import build_registry

    registry = build_registry()
    block = render_checks(registry)
    path = os.path.join(ROOT, "about.html")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if START not in text or END not in text:
        print("Маркеры CHECKS:START/END не найдены в about.html", file=sys.stderr)
        return 1
    new = apply(text, block)
    if args.check:
        if new != text:
            print(
                "about.html рассинхронизирован с реестром проверок. Запустите: python scripts/gen_about.py",
                file=sys.stderr,
            )
            return 1
        print(f"about.html синхронизирован: {len(registry)} проверок.")
        return 0
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    print(f"about.html обновлён: {len(registry)} проверок.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
