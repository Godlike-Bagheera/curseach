"""CLI-сканер: запуск без веб-UI, exit-code гейт по уровню (--fail-on).

Пример:
    python scripts/cli.py --url http://127.0.0.1:8000 --mode full --fail-on high --out report.sarif

Цель должна быть запущена отдельно (python start.py или uvicorn main:app).
Код возврата: 0 — гейт пройден, 1 — есть находки уровня --fail-on и выше.
"""

import argparse
import asyncio
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

LEVEL_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def gate_findings(findings: list[dict], fail_on: str) -> list[dict]:
    """Находки уровня fail-on и выше (CRITICAL >= HIGH >= MEDIUM >= LOW)."""
    if fail_on == "none":
        return []
    threshold = LEVEL_RANK[fail_on.upper()]
    return [f for f in findings if LEVEL_RANK.get(f.get("level", "LOW"), 99) <= threshold]


def main(argv=None) -> int:
    from scanner.reporting import results_to_sarif
    from scanner.tasks import AccountConfig, ScanTask, scan_engine

    ap = argparse.ArgumentParser(prog="curseach-cli", description="DAST-сканер API без UI, с exit-code гейтом")
    ap.add_argument("--url", required=True, help="URL цели (http://host:port)")
    ap.add_argument("--mode", default="full", choices=["quick", "full", "custom"])
    ap.add_argument("--checks", nargs="*", help="имена проверок для режима custom")
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "none"])
    ap.add_argument("--account", action="append", default=[], metavar="USER:PASS", help="аккаунт (можно два)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--out", default=None, help="куда сохранить SARIF")
    ap.add_argument("--json", default=None, help="куда сохранить находки (JSON)")
    args = ap.parse_args(argv)

    accounts = []
    for a in args.account:
        u, _, p = a.partition(":")
        accounts.append(AccountConfig(username=u, password=p))
    task = ScanTask(
        args.url,
        mode=args.mode,
        selected_checks=args.checks,
        seed=args.seed,
        account1=accounts[0] if accounts else None,
        account2=accounts[1] if len(accounts) > 1 else None,
    )
    asyncio.run(scan_engine(task))
    findings = task.scan_results
    print(f"[cli] status={task.status} findings={len(findings)} score={task.score} partial={task.partial}")
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        print(f"  {lvl}: {sum(1 for f in findings if f.get('level') == lvl)}")
    if args.out:
        sarif = results_to_sarif(args.url, time.strftime("%Y-%m-%dT%H:%M:%S"), findings)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(sarif, f, ensure_ascii=False, indent=2)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
    bad = gate_findings(findings, args.fail_on)
    if bad:
        print(f"[cli] GATE FAILED (--fail-on {args.fail_on}): {len(bad)} находок", file=sys.stderr)
        return 1
    print("[cli] GATE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
